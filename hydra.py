import argparse
import gzip
import json
import os
import socket
import ssl
import sys
import threading
from concurrent import futures
from html.parser import HTMLParser
from http.client import IncompleteRead, InvalidURL
from os import path
from queue import Empty, Queue
from socket import timeout as SocketTimeoutError
from urllib import error, parse, request


# Stable error category names written to the inventory's "error" field.
ERROR_TIMEOUT = "timeout"
ERROR_DNS = "dns_error"
ERROR_CONNECTION_REFUSED = "connection_refused"
ERROR_TLS = "tls_error"
ERROR_TOO_MANY_REDIRECTS = "too_many_redirects"
ERROR_INVALID_URL = "invalid_url"
ERROR_NETWORK = "network_error"

# Fields of one inventory line, in a fixed order.
INVENTORY_FIELDS = [
    "url",
    "parent",
    "depth",
    "tag",
    "attr",
    "status",
    "content_type",
    "bytes",
    "redirects",
    "elapsed_ms",
    "error",
    "checked_at",
]

# Default ports that disappear during URL normalization.
DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}


class TooManyRedirects(Exception):
    """Raised when a request follows more redirects than allowed."""


def _resolve_path_dots(url_path):
    """Resolve '.' and '..' segments in a URL path, preserving everything else.

    Unlike os.path normpath this keeps empty segments (double slashes) and a
    trailing slash, which are significant in URLs.
    """
    leading_slash = url_path.startswith("/")
    output = []
    for segment in url_path.split("/"):
        if segment == "..":
            if output and output[-1] not in ("", ".."):
                output.pop()
            elif not leading_slash:
                output.append("..")
        elif segment == ".":
            continue
        else:
            output.append(segment)
    resolved = "/".join(output)
    if leading_slash and not resolved.startswith("/"):
        resolved = "/" + resolved
    return resolved


def normalize_url(url):
    """Return the canonical form of an absolute URL for de-duplication.

    Rules: scheme and host are case-folded, default ports are removed, the
    fragment is dropped, an empty path becomes "/", and "."/".." path segments
    are resolved. The query string is kept verbatim and never reordered, so
    links differing only by query stay distinct.

    Raises ValueError for anything that is not an absolute URL.
    """
    parts = parse.urlsplit(url)
    if parts.scheme == "" or parts.hostname is None:
        raise ValueError("not an absolute URL: {0}".format(url))

    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    port = parts.port
    if port is not None and DEFAULT_PORTS.get(scheme) == port:
        port = None

    userinfo = ""
    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo += ":" + parts.password
        userinfo += "@"

    if ":" in host:  # IPv6 literal
        netloc = "{0}[{1}]".format(userinfo, host)
    else:
        netloc = userinfo + host
    if port is not None:
        netloc += ":" + str(port)

    normalized_path = _resolve_path_dots(parts.path or "/")
    # Fragment is deliberately discarded; query order is deliberately kept.
    return parse.urlunsplit((scheme, netloc, normalized_path, parts.query, ""))


def classify_error(exc):
    """Map a fetch exception to one of the stable ERROR_* category names."""
    if isinstance(exc, TooManyRedirects):
        return ERROR_TOO_MANY_REDIRECTS
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ERROR_TIMEOUT
    if isinstance(exc, ssl.SSLError):
        return ERROR_TLS
    if isinstance(exc, ConnectionRefusedError):
        return ERROR_CONNECTION_REFUSED
    if isinstance(exc, error.URLError):
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return ERROR_TIMEOUT
        if isinstance(reason, ssl.SSLError):
            return ERROR_TLS
        if isinstance(reason, ConnectionRefusedError):
            return ERROR_CONNECTION_REFUSED
        if isinstance(reason, socket.gaierror):
            return ERROR_DNS
        return ERROR_NETWORK
    if isinstance(exc, socket.gaierror):
        return ERROR_DNS
    if isinstance(exc, (InvalidURL, UnicodeError, TypeError, ValueError)):
        return ERROR_INVALID_URL
    return ERROR_NETWORK


class HostGate:
    """Per-host request spacing and concurrency limits (skeleton)."""

    def __init__(self, interval=0.0, max_per_host=0):
        self.interval = interval
        self.max_per_host = max_per_host

    def acquire(self, host):
        """Block until a request to host may start."""
        # Filled in a later step.
        raise NotImplementedError

    def release(self, host):
        """Release one concurrency slot for host."""
        # Filled in a later step.
        raise NotImplementedError


class InventoryStore:
    """Append-only JSONL inventory with resume support.

    One row per normalized URL. Rows are written one JSON object per line as
    soon as a probe finishes, each line flushed and fsynced so a killed
    process leaves no half line behind. On startup the existing file is
    merged: a trailing partial line (e.g. from SIGKILL mid-write) is ignored,
    later rows for the same key override earlier ones, and ordering follows
    the key's first appearance.
    """

    def __init__(self, filename=None, refresh=False):
        self.filename = filename
        self.refresh = refresh
        self._lock = threading.Lock()
        # key -> row; dict preserves first-insertion order.
        self._rows = {}
        # Keys whose row came from the current run's file (or a previous run)
        # and represents a successful probe. Used for resume skipping.
        self._success = set()
        self._file = None

    def load(self):
        """Merge any existing inventory rows into memory.

        Returns the number of complete rows read. A truncated final line is
        skipped rather than raising, so a crash mid-write stays recoverable.
        """
        if not self.filename or not os.path.exists(self.filename):
            return 0
        count = 0
        with open(self.filename, "r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    key = normalize_url(row["url"])
                except (ValueError, KeyError, json.JSONDecodeError):
                    # Partial line from a crash or otherwise unparseable row.
                    continue
                self._rows[key] = row
                if row.get("error") is None and row.get("status", 0) > 0:
                    self._success.add(key)
                count += 1
        return count

    def open_for_writing(self):
        """Open the inventory in append mode for incremental rows."""
        if self.filename:
            self._file = open(self.filename, "a", encoding="utf-8")

    def has(self, key):
        with self._lock:
            return key in self._rows

    def should_skip(self, key):
        """Resume rule: a previously successful row means no new request.

        --refresh ignores old results and re-probes everything.
        """
        if self.refresh:
            return False
        with self._lock:
            return key in self._success

    def record(self, row):
        """Overwrite the row for its key and append one full JSON line.

        The line is flushed and fsynced before returning, so on Ctrl-C or a
        killed process every persisted line is complete and independently
        parseable. With no filename the row stays in memory only.
        """
        try:
            key = normalize_url(row["url"])
        except ValueError:
            # An un-normalizable URL is keyed by its raw value so it still
            # gets exactly one row.
            key = row["url"]
        line = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self._rows[key] = row
            if row.get("error") is None and row.get("status", 0) > 0:
                self._success.add(key)
            elif key in self._success:
                self._success.discard(key)
            if self._file is not None:
                self._file.write(line + "\n")
                self._file.flush()
                os.fsync(self._file.fileno())

    def rows(self):
        """All current rows in first-appearance order."""
        with self._lock:
            return list(self._rows.values())

    def keys(self):
        with self._lock:
            return list(self._rows.keys())

    def get(self, key):
        with self._lock:
            return self._rows.get(key)

    def rewrite(self):
        """Write the de-duplicated rows back atomically.

        Appending across resume/refresh runs can leave superseded duplicate
        lines on disk; this rewrites the file via a temp file and os.replace
        so the on-disk inventory ends with exactly one line per key in
        first-appearance order.
        """
        if not self.filename:
            return
        tmp_name = self.filename + ".tmp"
        with open(tmp_name, "w", encoding="utf-8") as handle:
            for row in self.rows():
                handle.write(
                    json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, self.filename)

    def close(self):
        if self._file is not None:
            self._file.close()
            self._file = None


class Config:
    """Handle configuration"""

    def __init__(self, config_filename=""):
        # Use these default settings if no configuration file is provided
        self.tags = ["a", "link", "img", "script"]
        self.attrs = ["href", "src"]
        self.exclude_scheme_prefixes = ["tel:", "javascript:"]
        self.threads = 50
        self.timeout = 60
        self.OK = [200, 999]
        self.graceful_exit = False

        if config_filename != "":
            # Update settings if there is a config file
            with open(config_filename, "r") as file:
                file_text = file.read()
                config_json = json.loads(file_text)
                self.tags = config_json.get("tags", self.tags)
                self.attrs = config_json.get("attrs", self.attrs)
                self.exclude_scheme_prefixes = config_json.get(
                    "exclude_scheme_prefixes", self.exclude_scheme_prefixes
                )
                self.threads = config_json.get("threads", self.threads)
                self.timeout = config_json.get("timeout", self.timeout)
                self.OK = config_json.get("OK", self.OK)
                self.graceful_exit = config_json.get("graceful_exit", self.graceful_exit)

    def __str__(self):
        text = (
            f"tags: {self.tags}"
            f"attrs: {self.attrs}"
            f"exclude_scheme_prefixes = {self.exclude_scheme_prefixes}"
            f"threads = {self.threads}"
            f"timeout = {self.timeout}"
            f"OK = {self.OK}"
        )
        return text


class Parser(HTMLParser):
    """Parse tags found in webpages to get more links to check"""

    def __init__(self, config):
        super(Parser, self).__init__()
        self.links = []
        self.config = config

    def handle_starttag(self, tag, attrs):
        """Method html.parser.HTMLParser.handle_starttag"""
        # Ignore tags we aren't configured to check
        if tag not in self.config.tags:
            return
        for a in attrs:
            # Handle attributes we want to check while ignoring schemes we don't want to check
            # e.g. a 'href' with scheme 'tel:555...'
            # attrs is a list of (name, value) pairs
            if a[0] in self.config.attrs and a[1]:
                # TODO: handle an empty attribute value
                # Ignore schemes we aren't configured to check
                exclude_list = [
                    e for e in self.config.exclude_scheme_prefixes if a[1].startswith(e)
                ]
                if len(exclude_list) > 0:
                    return
                self.links.append(a[1])

    def feed_me(self, data):
        self.links = []
        self.feed(data)
        return self.links

    def error(self, msg):
        return msg


def extract_domain(link):
    """Extract domain of a link to help ensure we stay on the same website"""
    domain = parse.urlsplit(link).netloc
    return domain


class Checker:
    TO_PROCESS = Queue()

    def __init__(self, url, config):
        self.config = config
        self.broken = []
        self.domain = extract_domain(url)
        self.visited = set()
        self.mailto_links = list()
        self.pool = futures.ThreadPoolExecutor(max_workers=self.config.threads)
        self.report = ""
        # Number of jobs submitted but not yet finished. The crawler must not
        # stop while work is still in flight, since in-flight jobs discover and
        # enqueue more links via their done callback.
        self._lock = threading.Lock()
        self._pending = 0

    def add_entry(self, code, reason, page):
        """Add a link to the report"""
        if code in self.config.OK:
            return
        code = code
        reason = reason
        entry = {
            "code": code,
            "link": page["url"],
            "parent": page["parent"],
            "err": reason,
        }
        self.broken.append(entry)

    def load_url(self, page, timeout):
        """ Try to retrieve contents of a page and record result
            Store the link to be checked and its parent in the result
        """
        result = {
            "url": page["url"],
            "parent": page["parent"],
            "data": "",
            "valid_content_type": False,
        }

        # Use GET as HEAD is frequently not allowed
        r = request.Request(
            page["url"],
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"
            },
        )

        try:
            http_response = request.urlopen(r, timeout=self.config.timeout)

            encoding = http_response.headers.get("Content-Encoding")
            if encoding and "gzip" in encoding:
                data = gzip.decompress(http_response.read()).decode(
                    encoding="utf-8", errors="ignore"
                )
            elif encoding is None:
                data = http_response.read().decode(encoding="utf-8", errors="ignore")
            else:
                # Support for other less common directives not handled
                raise NotImplementedError
            result["data"] = data

            content_type = http_response.headers.get("Content-Type")
            if (
                content_type is not None
                and "text/html" in content_type
                or "text/plain" in content_type
            ):
                valid_content_type = True
            else:
                valid_content_type = False
            result["valid_content_type"] = valid_content_type

        except error.HTTPError as e:
            code = e.getcode()
            reason = e.reason
            self.add_entry(code, reason, page)
            return
        except (
            error.URLError,
            ConnectionRefusedError,
            ConnectionResetError,
            IncompleteRead,
            InvalidURL,
            NotImplementedError,
            SocketTimeoutError,
            TimeoutError,
            TypeError,
            UnicodeError,
        ) as e:
            code = 0
            reason = e
            self.add_entry(code, reason, page)
            return
        except TimeoutError as e:
            code = 408
            reason = e
            self.add_entry(code, reason, page)
            return

        return result

    def handle_future(self, result):
        if result.result():
            page = result.result()
            self.parse_page(page)

    def _job_done(self, future):
        """Done callback: process the result, then mark the job complete.

        The decrement runs in a finally block so a job that raises still
        releases its pending slot and can never wedge the crawler open.
        """
        try:
            self.handle_future(future)
        finally:
            with self._lock:
                self._pending -= 1

    def parse_page(self, page):
        """Get more links from successfully retrieved pages in the same domain"""
        if self.domain == extract_domain(page["url"]) and page["valid_content_type"]:
            parent = page["url"]
            parser = Parser(self.config)
            links = parser.feed_me(page["data"])
            new_links = [x for x in links if x not in self.visited]
            full_links = [parse.urljoin(parent, l) for l in new_links]
            for l in full_links:
                if l not in self.visited:
                    li = {"parent": parent, "url": l}
                    self.TO_PROCESS.put(li)

    def make_report(self):
        """Parse broken links list into YAML report"""
        self.report = "---\ntitle: Broken Link Report"
        self.report += "\nchecked: " + str(len(self.visited))
        self.report += "\nnumber of email links: " + str(len(self.mailto_links))
        self.report += "\nemails: " + ", ".join(
            [str(m) for m in set(self.mailto_links)]
        )
        self.report += "\nbroken: " + str(len(self.broken))
        self.report += "\n---\n"
        sorted_list = sorted(self.broken, key=lambda k: k["code"], reverse=True)
        for link in sorted_list:
            self.report += f"\n- code:    {link['code']}\n  url:     {link['link']}\n  parent:  {link['parent']}\n  error:   {link['err']}\n"
        return self.report

    def run(self):
        """Run crawler until the queue is drained and no jobs are in flight.

        Stopping on an empty queue alone is a race: a worker may still be
        fetching a page whose links have not been enqueued yet, which makes
        the number of links checked vary between runs. Only stop once the
        queue is empty *and* there is no pending work.
        """
        while True:
            try:
                target_url = self.TO_PROCESS.get(block=True, timeout=1)
            except Empty:
                with self._lock:
                    if self._pending == 0:
                        return
                continue

            try:
                if target_url["url"].startswith("mailto:"):
                    email = target_url["url"][len("mailto:") :]
                    self.mailto_links.append(email)

                elif target_url["url"] not in self.visited:
                    self.visited.add(target_url["url"])
                    with self._lock:
                        self._pending += 1
                    job = self.pool.submit(
                        self.load_url, target_url, self.config.timeout
                    )
                    job.add_done_callback(self._job_done)
            except Exception as e:
                print(e)


def main():
    """Validate arguments and run Hydra"""
    parg = argparse.ArgumentParser(
        description="Crawl a website and check for broken links.",
        epilog="A broken links report will be output to stdout, so you may like to redirect this to a file.",
    )
    parg.add_argument(
        "URL", help="The URL of the website to crawl, e.g. https://example.com"
    )
    parg.add_argument("--config", "-c", help="Path to a configuration file")
    args = parg.parse_args()

    # If a configuration file path was provided, ensure we can find it
    if args.config and not path.exists(args.config):
        print(f"Can't find {args.config} as config file.")
        sys.exit(1)

    # Ensure we have a valid URL to crawl
    url = args.URL
    check_url = parse.urlparse(url)
    if check_url.scheme == "" or check_url.netloc == "":
        print("Please provide a valid URL with scheme, e.g. https://example.com")
        sys.exit(1)

    # Configure and run Hydra
    first_url = {"parent": url, "url": url}
    config_file = ""  # Uses default settings if no configuration file provided
    if args.config:
        config_file = args.config
    config = Config(config_file)
    check = Checker(url, config)
    check.TO_PROCESS.put(first_url)
    check.run()
    print(check.make_report())

    if check.broken and not check.config.graceful_exit:
        sys.exit(1)


if __name__ == "__main__":
    main()
