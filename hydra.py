import argparse
import gzip
import json
import os
import socket
import ssl
import sys
import threading
import time
import uuid
from concurrent import futures
from datetime import datetime, timezone
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


class RedirectRecorder(request.HTTPRedirectHandler):
    """Record every hop of a redirect chain and enforce a hop limit.

    Installed ahead of urllib's default redirect handler so it owns redirect
    decisions. "redirects" ends up as the chain from the first jump's
    Location through the final landed URL; no redirects means an empty list.
    """

    max_redirections = 10

    def __init__(self):
        self.redirects = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if len(self.redirects) >= self.max_redirections:
            raise TooManyRedirects(
                "more than {0} redirects".format(self.max_redirections)
            )
        target = request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl
        )
        if target is None:
            raise TooManyRedirects("unsupported redirect to {0}".format(newurl))
        self.redirects.append(target.full_url)
        return target


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
    if isinstance(exc, socket.gaierror):
        return ERROR_DNS
    if isinstance(exc, error.URLError):
        # urllib wraps the real network failure as the "reason"; unwrap it
        # before falling back to a generic network error.
        return classify_error(getattr(exc, "reason", exc))
    if isinstance(exc, (InvalidURL, UnicodeError, TypeError, ValueError)):
        return ERROR_INVALID_URL
    return ERROR_NETWORK


class HostGate:
    """Per-host request spacing and concurrency limits.

    Different hosts stay independent, so requests to host B never wait on
    limits for host A; overall parallelism is still bounded by the
    ThreadPoolExecutor's thread count. interval/max_per_host of 0 mean
    unlimited.
    """

    def __init__(self, interval=0.0, max_per_host=0):
        self.interval = float(interval)
        self.max_per_host = int(max_per_host) if max_per_host else 0
        self._cond = threading.Condition()
        # host -> {"in_flight": int, "next_allowed_at": monotonic timestamp}
        self._hosts = {}

    def _state(self, host):
        state = self._hosts.get(host)
        if state is None:
            state = {"in_flight": 0, "next_allowed_at": 0.0}
            self._hosts[host] = state
        return state

    def acquire(self, host):
        """Block until a request to host may start, then take a slot."""
        if self.interval == 0.0 and self.max_per_host == 0:
            return
        with self._cond:
            state = self._state(host)
            while True:
                now = time.monotonic()
                concurrency_ok = (
                    self.max_per_host == 0
                    or state["in_flight"] < self.max_per_host
                )
                wait_for = state["next_allowed_at"] - now
                if concurrency_ok and wait_for <= 0:
                    state["in_flight"] += 1
                    if self.interval > 0:
                        state["next_allowed_at"] = now + self.interval
                    return
                # Two independent waits: a release notifies waiters when a
                # concurrency slot frees up; the interval simply times out.
                if not concurrency_ok:
                    self._cond.wait(
                        timeout=wait_for if wait_for > 0 else None
                    )
                else:
                    self._cond.wait(timeout=wait_for)

    def release(self, host):
        """Release one concurrency slot for host."""
        if self.max_per_host == 0:
            return
        with self._cond:
            state = self._state(host)
            if state["in_flight"] > 0:
                state["in_flight"] -= 1
            self._cond.notify_all()


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
        self.link_refs = []
        self._capture = False
        self.config = config

    def feed_me(self, data):
        self.links = []
        self.feed(data)
        return self.links

    def feed_me_refs(self, data):
        """Like feed_me, but keep the (tag, attribute, raw value) per link."""
        self.link_refs = []
        self._capture = True
        self.links = []
        self.feed(data)
        self._capture = False
        return self.link_refs

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
                if getattr(self, "_capture", False):
                    self.link_refs.append({"tag": tag, "attr": a[0], "value": a[1]})

    def error(self, msg):
        return msg


def extract_domain(link):
    """Extract domain of a link to help ensure we stay on the same website"""
    domain = parse.urlsplit(link).netloc
    return domain


class Checker:
    TO_PROCESS = Queue()

    def __init__(self, url, config, inventory=None, gate=None):
        self.config = config
        self.inventory = inventory
        self.gate = gate
        self.broken = []
        self.domain = extract_domain(url)
        self.visited = set()
        # De-duplication set keyed by normalized URL; self.visited keeps the
        # raw URLs for the existing YAML report ("checked" count etc.).
        self.seen_keys = set()
        self.mailto_links = list()
        self.pool = futures.ThreadPoolExecutor(max_workers=self.config.threads)
        self.report = ""
        # Number of jobs submitted but not yet finished. The crawler must not
        # stop while work is still in flight, since in-flight jobs discover and
        # enqueue more links via their done callback.
        self._lock = threading.Lock()
        self._pending = 0
        # Probe counters for the summary file.
        self.checked = 0
        self.skipped = 0
        self.seed_url = url

    def _make_row(self, page):
        """Build an inventory row skeleton for page with the fixed fields."""
        return {
            "url": page["url"],
            "parent": page["parent"],
            "depth": page.get("depth", 0),
            "tag": page.get("tag", ""),
            "attr": page.get("attr", ""),
            "status": 0,
            "content_type": "",
            "bytes": 0,
            "redirects": [],
            "elapsed_ms": 0,
            "error": None,
            "checked_at": "",
        }

    def _record_row(self, row):
        """Persist one row (immediately) or keep it in memory."""
        if self.inventory is not None:
            self.inventory.record(row)

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
        """Retrieve a page, record one inventory row, return crawl data.

        On success the result dict feeds parse_page exactly as before, so the
        YAML broken-links report is unchanged. Every probe — success, HTTP
        error status, or network-layer failure — writes exactly one inventory
        row. A failure here never raises into the thread pool.
        """
        row = self._make_row(page)
        started = time.monotonic()

        # Use GET as HEAD is frequently not allowed
        r = request.Request(
            page["url"],
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"
            },
        )
        recorder = RedirectRecorder()
        # An empty ProxyHandler makes every connection direct regardless of
        # proxy environment variables, which can otherwise turn a local
        # connection refusal into a proxy's 502 response.
        opener = request.build_opener(recorder, request.ProxyHandler({}))

        host = extract_domain(page["url"])
        if self.gate is not None:
            self.gate.acquire(host)
        try:
            try:
                http_response = opener.open(r, timeout=self.config.timeout)
            except error.HTTPError as e:
                # We got a response: record its final status, not an error
                # category. The YAML report still lists it as broken.
                self._finish_timing(row, started)
                row["status"] = e.getcode()
                row["content_type"] = e.headers.get("Content-Type") or ""
                row["redirects"] = list(recorder.redirects)
                self.add_entry(e.getcode(), e.reason, page)
                self._record_row(row)
                return None
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
                OSError,
            ) as e:
                # No response at all: network-layer problem with a stable
                # category name. The old behavior recorded code 0 here.
                self._finish_timing(row, started)
                row["status"] = 0
                row["redirects"] = list(recorder.redirects)
                row["error"] = classify_error(e)
                self.add_entry(0, e, page)
                self._record_row(row)
                return None

            raw_body = b""
            try:
                raw_body = http_response.read()
                encoding = http_response.headers.get("Content-Encoding")
                if encoding and "gzip" in encoding:
                    data = gzip.decompress(raw_body).decode(
                        encoding="utf-8", errors="ignore"
                    )
                elif encoding is None:
                    data = raw_body.decode(encoding="utf-8", errors="ignore")
                else:
                    # Support for other less common directives not handled
                    raise NotImplementedError
            except (IncompleteRead, NotImplementedError, OSError) as e:
                self._finish_timing(row, started)
                row["status"] = http_response.getcode()
                row["content_type"] = (
                    http_response.headers.get("Content-Type") or ""
                )
                row["bytes"] = len(raw_body)
                row["redirects"] = list(recorder.redirects)
                row["error"] = classify_error(e)
                self.add_entry(0, e, page)
                self._record_row(row)
                return None

            self._finish_timing(row, started)
            row["status"] = http_response.getcode()
            row["content_type"] = http_response.headers.get("Content-Type") or ""
            row["bytes"] = len(raw_body)
            row["redirects"] = list(recorder.redirects)
            self._record_row(row)
        finally:
            if self.gate is not None:
                self.gate.release(host)

        content_type = row["content_type"]
        valid_content_type = (
            content_type is not None
            and ("text/html" in content_type or "text/plain" in content_type)
        )

        result = {
            "url": page["url"],
            "parent": page["parent"],
            "data": data,
            "valid_content_type": valid_content_type,
        }
        return result

    @staticmethod
    def _finish_timing(row, started):
        row["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        row["checked_at"] = datetime.now(timezone.utc).isoformat()

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
            parent_depth = page.get("depth", 0)
            parser = Parser(self.config)
            refs = parser.feed_me_refs(page["data"])
            for ref in refs:
                full_link = parse.urljoin(parent, ref["value"])
                if full_link in self.visited:
                    continue
                li = {
                    "parent": parent,
                    "url": full_link,
                    "depth": parent_depth + 1,
                    "tag": ref["tag"],
                    "attr": ref["attr"],
                }
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

    def prime_from_inventory(self):
        """Re-enqueue rows already known to the inventory.

        On resume after a crash the crawl ancestor chain may be broken, so
        every previously discovered URL is put back in the queue. Successful
        rows are skipped in run(); failed rows get re-probed. Metadata from
        the old row (parent/depth/tag/attr) is carried over.
        """
        if self.inventory is None:
            return
        for row in self.inventory.rows():
            self.TO_PROCESS.put(
                {
                    "parent": row["parent"],
                    "url": row["url"],
                    "depth": row.get("depth", 0),
                    "tag": row.get("tag", ""),
                    "attr": row.get("attr", ""),
                }
            )

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
                    continue

                # Canonical de-dup key; fall back to the raw URL when a link
                # cannot be normalized so it still gets probed exactly once.
                try:
                    key = normalize_url(target_url["url"])
                except ValueError:
                    key = target_url["url"]

                if key in self.seen_keys or target_url["url"] in self.visited:
                    continue

                if self.inventory is not None and self.inventory.should_skip(key):
                    # Resume: a previous successful probe, no request sent.
                    self.seen_keys.add(key)
                    self.visited.add(target_url["url"])
                    with self._lock:
                        self.skipped += 1
                    continue

                self.seen_keys.add(key)
                self.visited.add(target_url["url"])
                with self._lock:
                    self._pending += 1
                    self.checked += 1
                job = self.pool.submit(
                    self.load_url, target_url, self.config.timeout
                )
                job.add_done_callback(self._job_done)
            except Exception as e:
                print(e)


    def build_summary(self, run_id, started_at, finished_at):
        """Build the summary dict, with every count derived from inventory rows.

        Computing the distributions from the final rows rather than from
        separate counters means the summary can never disagree with the
        inventory.
        """
        rows = self.inventory.rows() if self.inventory is not None else []
        discovered = len(rows)
        # Probed this run = everything not skipped; skipped is tracked live.
        probed = discovered - self.skipped
        status_dist = {}
        error_dist = {}
        success = 0
        failure = 0
        for row in rows:
            if row.get("error"):
                error_name = row["error"]
                error_dist[error_name] = error_dist.get(error_name, 0) + 1
                failure += 1
            else:
                code = str(row.get("status", 0))
                status_dist[code] = status_dist.get(code, 0) + 1
                if row.get("status", 0) in self.config.OK:
                    success += 1
                else:
                    failure += 1
        return {
            "run_id": run_id,
            "started_at": started_at,
            "finished_at": finished_at,
            "seed_url": self.seed_url,
            "discovered": discovered,
            "probed": probed,
            "skipped": self.skipped,
            "successful": success,
            "failed": failure,
            "status_distribution": status_dist,
            "error_distribution": error_dist,
        }


def write_summary_atomic(filename, summary):
    """Overwrite the summary file atomically; only called after a full run."""
    tmp_name = filename + ".tmp"
    with open(tmp_name, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_name, filename)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


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
    parg.add_argument(
        "--inventory",
        help="Path to the JSON-lines inventory file; one complete row is "
        "appended per link as it is probed. Re-running with the same file "
        "resumes from its successful rows.",
    )
    parg.add_argument(
        "--summary",
        help="Path to the JSON run summary, overwritten after a full run. "
        "Requires --inventory.",
    )
    parg.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore previous inventory results and re-probe every link, "
        "overwriting rows in place.",
    )
    parg.add_argument(
        "--per-host-interval",
        type=float,
        default=0.0,
        help="Minimum seconds between request starts to the same host "
        "(default: 0, no limit).",
    )
    parg.add_argument(
        "--max-per-host",
        type=int,
        default=0,
        help="Maximum simultaneous requests to the same host "
        "(default: 0, no limit).",
    )
    args = parg.parse_args()

    # If a configuration file path was provided, ensure we can find it
    if args.config and not path.exists(args.config):
        print(f"Can't find {args.config} as config file.")
        sys.exit(1)

    if args.summary and not args.inventory:
        print("--summary requires --inventory.")
        sys.exit(1)

    # Ensure we have a valid URL to crawl
    url = args.URL
    check_url = parse.urlparse(url)
    if check_url.scheme == "" or check_url.netloc == "":
        print("Please provide a valid URL with scheme, e.g. https://example.com")
        sys.exit(1)

    # Configure and run Hydra
    config_file = ""  # Uses default settings if no configuration file provided
    if args.config:
        config_file = args.config
    config = Config(config_file)

    inventory = None
    if args.inventory:
        inventory = InventoryStore(args.inventory, refresh=args.refresh)
        inventory.load()
        inventory.open_for_writing()

    gate = None
    if args.per_host_interval > 0 or args.max_per_host > 0:
        gate = HostGate(args.per_host_interval, args.max_per_host)

    check = Checker(url, config, inventory=inventory, gate=gate)
    check.prime_from_inventory()
    check.TO_PROCESS.put(
        {"parent": url, "url": url, "depth": 0, "tag": "", "attr": ""}
    )

    run_id = uuid.uuid4().hex
    started_at = utc_now_iso()
    interrupted = False
    try:
        check.run()
    except KeyboardInterrupt:
        # Rows already appended are complete lines; just stop cleanly. The
        # summary is intentionally not written on an interrupted run.
        interrupted = True
    finally:
        check.pool.shutdown(wait=True)
        if inventory is not None:
            inventory.close()

    print(check.make_report())

    if interrupted:
        sys.exit(130)

    if inventory is not None:
        # Collapse append-only history to one line per key, in first-seen order.
        inventory.rewrite()
        if args.summary:
            finished_at = utc_now_iso()
            summary = check.build_summary(run_id, started_at, finished_at)
            write_summary_atomic(args.summary, summary)

    if check.broken and not check.config.graceful_exit:
        sys.exit(1)


if __name__ == "__main__":
    main()
