import functools
import http.server
import json
import os
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib import error

HYDRA = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "hydra.py"))

from hydra import (
    Checker,
    Config,
    HostGate,
    INVENTORY_FIELDS,
    InventoryStore,
    Parser,
    TooManyRedirects,
    classify_error,
    extract_domain,
    normalize_url,
)

HTMLDATA = os.path.join(os.path.dirname(__file__), "data/test-page.html")
CONFIGDATA = os.path.join(os.path.dirname(__file__), "data/basic_config.json")


class TestCases(unittest.TestCase):
    """Open and close file from data/"""

    def setUp(self):
        self.testfile = open(HTMLDATA)
        self.data = self.testfile.read()
        self.url = "https://example.com"
        self.check = Checker(self.url, Config())
        self.parser = Parser(Config())

    def tearDown(self):
        self.testfile.close()

    def test_parser_expected_output(self):
        """ Parser gives expected values"""
        links = self.parser.feed_me(self.data)
        expected_output = [
            "style.css",
            "scripts.js",
            "http://baddomain.com/i-donut-exist",
            "image.png",
            "www.anotherbaddomain.com/multithreading-is-fun",
            "https://example.com/i-have-links",
            "https://example.com",
        ]
        self.assertEqual(links, expected_output)

    def test_domain_extraction(self):
        """Checker uses correct domain for comparison"""
        self.assertEqual(extract_domain(self.url), "example.com")

    def test_process_queue_length(self):
        """Checker doesn't add visited links to queue"""
        self.pagedata = {
            "url": "https://example.com/test-page.html",
            "parent": "https://example.com/test-page.html",
            "data": """
                <!DOCTYPE html>\n
                <html>\n\n
                <head>\n
                    <title>Test Data Page</title>\n\n
                    <meta charset="utf-8">\n
                    <meta http-equiv="Content-type" content="text/html; charset=UTF-8">\n
                    <meta name="viewport" content="width=device-width, initial-scale=1">\n
                    <link rel="stylesheet" href="style.css" type="text/css">\n
                    <script type="text/javascript" src="scripts.js"></script>\n
                </head>\n\n
                <body>\n
                    <div>\n
                        <h1>Test Data Page</h1>\n
                        <p>This page does not exist: <a href="/i-donut-exist">Whale</a></p>\n
                        <p>This is not a link: <a>No Spoon</a></p>\n
                        <img src="image.png" />\n
                        <p>This page does not exist: <a href="/multithreading-is-fun">Petunias</a></p>\n
                        <p>This page contains more links: <a href="/i-have-links">Crawl Me</a></p>\n
                        <p>This domain is for use in illustrative examples in documents. You may use this\n
                            domain in literature without prior coordination or asking for permission:
                            <a href="https://example.com">Example</a>
                        </p>\n
                     </div>\n\n\n
                </body>\n
                </html>'
            """,
            "valid_content_type": True,
        }
        # There are 7 links in pagedata["data"]
        first_parse = 7
        self.check.parse_page(self.pagedata)
        self.assertEqual(len(self.check.TO_PROCESS.queue), first_parse)
        self.check.visited.add("https://example.com/style.css")
        # Checker should add to queue all but the one visited link
        second_parse = 13
        self.check.parse_page(self.pagedata)
        self.assertEqual(len(self.check.TO_PROCESS.queue), second_parse)

    def test_run_visits_all_links_despite_lulls(self):
        """run() drains the whole site even when jobs finish slowly.

        Regression test for inconsistent results: the crawler must not stop
        while a worker is still in flight. Each fake fetch sleeps, so the
        queue goes empty while a job is pending; only the pending-job guard
        keeps the crawl going until every page is visited.
        """
        check = Checker("https://example.com", Config())
        # The work queue is shared across Checker instances, so isolate it.
        with check.TO_PROCESS.mutex:
            check.TO_PROCESS.queue.clear()

        pages = {
            "https://example.com": '<a href="https://example.com/a">a</a>',
            "https://example.com/a": '<a href="https://example.com/b">b</a>',
            "https://example.com/b": "<p>no more links</p>",
        }

        def fake_load_url(page, timeout):
            time.sleep(0.05)  # simulate latency so the queue empties mid-flight
            return {
                "url": page["url"],
                "parent": page["parent"],
                "data": pages.get(page["url"], ""),
                "valid_content_type": True,
            }

        check.load_url = fake_load_url
        check.TO_PROCESS.put(
            {"parent": "https://example.com", "url": "https://example.com"}
        )
        check.run()

        self.assertEqual(
            check.visited,
            {
                "https://example.com",
                "https://example.com/a",
                "https://example.com/b",
            },
        )

    def test_end_to_end_crawl_over_http(self):
        """Crawl a real site served on localhost, end to end.

        The other tests call parse_page directly and never make a request, so
        the urllib fetch, response handling, and the run() queue/thread loop go
        unexercised. Serve a tiny fixture site and assert Hydra crawls the good
        pages and reports exactly the one broken link. Self-contained: binds to
        127.0.0.1 on an ephemeral port, so it needs no internet access.
        """
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, "index.html"), "w") as f:
            f.write('<a href="page2.html">ok</a><a href="missing.html">broken</a>')
        with open(os.path.join(tmpdir, "page2.html"), "w") as f:
            f.write('<a href="index.html">home</a>')

        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass  # keep test output clean

        handler = functools.partial(QuietHandler, directory=tmpdir)
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            url = f"http://127.0.0.1:{port}/"
            check = Checker(url, Config())
            # TO_PROCESS is shared across Checker instances; start from empty.
            with check.TO_PROCESS.mutex:
                check.TO_PROCESS.queue.clear()
            check.TO_PROCESS.put({"parent": url, "url": url})
            check.run()
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(
            len(check.broken), 1, f"expected one broken link, got {check.broken}"
        )
        self.assertEqual(check.broken[0]["code"], 404)
        self.assertTrue(check.broken[0]["link"].endswith("/missing.html"))
        # The seed page and the good internal page were both crawled.
        self.assertGreaterEqual(len(check.visited), 2)

    def test_read_config_without_file(self):
        # Arrange

        # Act
        results = Config()

        # Assert
        expected = (
            f"tags: ['a', 'link', 'img', 'script']"
            f"attrs: ['href', 'src']"
            f"exclude_scheme_prefixes = ['tel:', 'javascript:']"
            f"threads = 50"
            f"timeout = 60"
            f"OK = [200, 999]"
        )
        self.assertEqual(str(results), expected)

    def test_read_config_with_valid_config_file(self):
        # Arrange

        # Act
        results = Config(CONFIGDATA)

        # Assert
        expected = (
            f"tags: ['a', 'img']"
            f"attrs: ['href']"
            f"exclude_scheme_prefixes = ['tel']"
            f"threads = 25"
            f"timeout = 30"
            f"OK = [200, 999, 403]"
        )
        self.assertEqual(str(results), expected)


class TestNormalization(unittest.TestCase):
    """normalize_url implements the de-duplication rules from the spec."""

    def test_scheme_and_host_case_insensitive(self):
        self.assertEqual(
            normalize_url("HTTPS://Example.COM/path"),
            "https://example.com/path",
        )

    def test_default_ports_removed_others_kept(self):
        self.assertEqual(normalize_url("http://example.com:80/a"), "http://example.com/a")
        self.assertEqual(normalize_url("https://example.com:443/a"), "https://example.com/a")
        self.assertEqual(
            normalize_url("https://example.com:8443/a"),
            "https://example.com:8443/a",
        )

    def test_fragment_removed(self):
        self.assertEqual(
            normalize_url("https://example.com/a#frag"),
            "https://example.com/a",
        )

    def test_empty_path_becomes_slash(self):
        self.assertEqual(normalize_url("https://example.com"), "https://example.com/")
        self.assertEqual(normalize_url("https://example.com?x=1"), "https://example.com/?x=1")

    def test_dot_segments_resolved(self):
        self.assertEqual(
            normalize_url("https://example.com/a/b/./c/../d"),
            "https://example.com/a/b/d",
        )
        self.assertEqual(
            normalize_url("https://example.com/../a"),
            "https://example.com/a",
        )

    def test_double_slash_and_trailing_slash_preserved(self):
        self.assertEqual(
            normalize_url("https://example.com/a//b/"),
            "https://example.com/a//b/",
        )

    def test_query_kept_verbatim_and_distinct(self):
        self.assertEqual(
            normalize_url("https://example.com/a?b=2&a=1"),
            "https://example.com/a?b=2&a=1",
        )
        self.assertNotEqual(
            normalize_url("https://example.com/a?x=1"),
            normalize_url("https://example.com/a?x=2"),
        )

    def test_invalid_urls_raise(self):
        for bad in ("not a url", "/relative/path", "//example.com/no-scheme"):
            with self.assertRaises(ValueError):
                normalize_url(bad)

    def test_ipv6_and_userinfo_kept(self):
        self.assertEqual(
            normalize_url("http://user:pass@[::1]:8080/x"),
            "http://user:pass@[::1]:8080/x",
        )


class TestErrorClassification(unittest.TestCase):
    """classify_error returns one stable category name per failure mode."""

    def test_known_categories(self):
        cases = [
            (socket.timeout(), "timeout"),
            (TimeoutError(), "timeout"),
            (socket.gaierror("[Errno -2] Name or service not known"), "dns_error"),
            (ConnectionRefusedError(), "connection_refused"),
            (ssl.SSLError("handshake failure"), "tls_error"),
            (TooManyRedirects(), "too_many_redirects"),
            (ValueError("bad url"), "invalid_url"),
        ]
        for exc, expected in cases:
            with self.subTest(exc=exc):
                self.assertEqual(classify_error(exc), expected)

    def test_urlerror_reasons_unwrapped(self):
        self.assertEqual(
            classify_error(error.URLError(socket.timeout())),
            "timeout",
        )
        self.assertEqual(
            classify_error(error.URLError(ssl.SSLError("boom"))),
            "tls_error",
        )
        self.assertEqual(
            classify_error(error.URLError(ConnectionRefusedError())),
            "connection_refused",
        )
        self.assertEqual(
            classify_error(error.URLError(socket.gaierror())),
            "dns_error",
        )
        self.assertEqual(
            classify_error(error.URLError("plain string reason")),
            "network_error",
        )

    def test_unknown_exception_is_network_error(self):
        self.assertEqual(classify_error(OSError("mystery")), "network_error")


def make_row(url, parent=None, status=200, error=None, **overrides):
    """Build an inventory row with the fixed field set for use in tests."""
    row = {
        "url": url,
        "parent": parent if parent is not None else url,
        "depth": overrides.pop("depth", 0),
        "tag": overrides.pop("tag", ""),
        "attr": overrides.pop("attr", ""),
        "status": status,
        "content_type": overrides.pop("content_type", "text/html"),
        "bytes": overrides.pop("bytes", 0),
        "redirects": overrides.pop("redirects", []),
        "elapsed_ms": overrides.pop("elapsed_ms", 1),
        "error": error,
        "checked_at": overrides.pop(
            "checked_at", "2026-01-01T00:00:00+00:00"
        ),
    }
    row.update(overrides)
    return row


class TestInventoryStore(unittest.TestCase):
    """JSONL inventory: merge, resume skip, refresh overwrite, half lines."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        )
        self.tmp.close()
        self.path = self.tmp.name

    def tearDown(self):
        os.unlink(self.path)

    def _read_lines(self):
        with open(self.path, "r", encoding="utf-8") as handle:
            return [line for line in handle.read().splitlines() if line]

    def test_rows_appended_one_json_per_line_and_parseable(self):
        store = InventoryStore(self.path)
        store.open_for_writing()
        store.record(make_row("https://example.com/a"))
        store.record(make_row("https://example.com/b"))
        store.close()

        lines = self._read_lines()
        self.assertEqual(len(lines), 2)
        parsed = [json.loads(line) for line in lines]
        self.assertEqual([row["url"] for row in parsed], [
            "https://example.com/a",
            "https://example.com/b",
        ])
        for row in parsed:
            self.assertEqual(list(row.keys()), INVENTORY_FIELDS)

    def test_half_written_final_line_is_ignored_on_merge(self):
        good = make_row("https://example.com/good")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(good) + "\n")
            handle.write('{"url": "https://example.com/half", "stat')  # no newline

        store = InventoryStore(self.path)
        loaded = store.load()
        self.assertEqual(loaded, 1)
        self.assertTrue(store.has(normalize_url("https://example.com/good")))
        self.assertFalse(store.has(normalize_url("https://example.com/half")))

    def test_merge_dedupes_latest_wins_but_order_is_first_seen(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(make_row("https://example.com/a", status=200)) + "\n")
            handle.write(json.dumps(make_row("https://example.com/b", status=200)) + "\n")
            # Same normalized URL as the first row, different case/port.
            handle.write(
                json.dumps(make_row("https://EXAMPLE.com:443/a", status=500)) + "\n"
            )

        store = InventoryStore(self.path)
        store.load()
        rows = store.rows()
        # One row per normalized key, ordered by first appearance.
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            [normalize_url(r["url"]) for r in rows],
            ["https://example.com/a", "https://example.com/b"],
        )
        # The later line overwrites the earlier one, raw spelling included.
        self.assertEqual(rows[0]["url"], "https://EXAMPLE.com:443/a")
        self.assertEqual(rows[0]["status"], 500)

    def test_resume_skips_successful_rows_but_retries_failures(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(make_row("https://example.com/ok", status=200)) + "\n")
            handle.write(
                json.dumps(make_row("https://example.com/bad", status=0, error="dns_error"))
                + "\n"
            )

        store = InventoryStore(self.path)
        store.load()
        self.assertTrue(store.should_skip(normalize_url("https://example.com/ok")))
        self.assertFalse(store.should_skip(normalize_url("https://example.com/bad")))

    def test_refresh_reprobes_everything(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(make_row("https://example.com/ok", status=200)) + "\n")

        store = InventoryStore(self.path, refresh=True)
        store.load()
        self.assertFalse(store.should_skip(normalize_url("https://example.com/ok")))
        # Old rows are still known, so a refresh overwrites in place.
        self.assertTrue(store.has(normalize_url("https://example.com/ok")))

    def test_reprobe_overwrites_same_row_and_keeps_first_order(self):
        store = InventoryStore(self.path)
        store.open_for_writing()
        store.record(make_row("https://example.com/a", status=200))
        store.record(make_row("https://example.com/b", status=200))
        store.record(make_row("https://example.com/a", status=404))
        store.close()

        rows = store.rows()
        self.assertEqual([r["url"] for r in rows], [
            "https://example.com/a",
            "https://example.com/b",
        ])
        self.assertEqual(rows[0]["status"], 404)

    def test_rewrite_leaves_one_line_per_key(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(make_row("https://example.com/a", status=200)) + "\n")
            handle.write(json.dumps(make_row("https://example.com/b", status=200)) + "\n")
            handle.write(
                json.dumps(make_row("https://EXAMPLE.COM/a", status=404)) + "\n"
            )

        store = InventoryStore(self.path)
        store.load()
        store.rewrite()

        lines = self._read_lines()
        self.assertEqual(len(lines), 2)
        keys = [normalize_url(json.loads(line)["url"]) for line in lines]
        self.assertEqual(keys, ["https://example.com/a", "https://example.com/b"])
        self.assertEqual(json.loads(lines[0])["status"], 404)

    def test_in_memory_store_without_filename(self):
        store = InventoryStore()
        store.record(make_row("https://example.com/a"))
        self.assertEqual(len(store.rows()), 1)
        store.rewrite()  # must be a no-op, not an error
        store.close()


class TestHostGate(unittest.TestCase):
    """Per-host concurrency cap and request interval."""

    def test_unlimited_gate_never_blocks(self):
        gate = HostGate()  # 0, 0 means no limits
        for _ in range(20):
            gate.acquire("h")
        # release on an unlimited gate is a harmless no-op
        for _ in range(20):
            gate.release("h")

    def test_concurrency_cap_never_exceeded(self):
        gate = HostGate(max_per_host=2)
        peak = [0]
        peak_lock = threading.Lock()
        stop = threading.Event()

        def worker():
            while not stop.is_set():
                gate.acquire("h")
                with peak_lock:
                    peak[0] = max(peak[0], gate._hosts["h"]["in_flight"])
                time.sleep(0.01)
                gate.release("h")

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        time.sleep(0.3)
        stop.set()
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(peak[0], 2)

    def test_interval_spaces_request_starts(self):
        gate = HostGate(interval=0.2)
        starts = []
        for _ in range(3):
            gate.acquire("h")
            starts.append(time.monotonic())
            gate.release("h")
        gaps = [starts[i + 1] - starts[i] for i in range(len(starts) - 1)]
        for gap in gaps:
            self.assertGreaterEqual(gap, 0.19)

    def test_different_hosts_do_not_block_each_other(self):
        gate = HostGate(max_per_host=1)
        gate.acquire("a")  # host a is now at its cap
        # host b must still be acquirable immediately
        ready = threading.Event()

        def grab_b():
            gate.acquire("b")
            ready.set()
            gate.release("b")

        thread = threading.Thread(target=grab_b)
        thread.start()
        self.assertTrue(ready.wait(timeout=1.0))
        thread.join()
        gate.release("a")

    def test_cap_blocks_then_releases(self):
        gate = HostGate(max_per_host=1)
        gate.acquire("h")
        got = threading.Event()

        def second():
            gate.acquire("h")
            got.set()
            gate.release("h")

        thread = threading.Thread(target=second)
        thread.start()
        self.assertFalse(got.wait(timeout=0.15))
        gate.release("h")
        self.assertTrue(got.wait(timeout=1.0))
        thread.join()


def start_fixture_server(pages, port=0):
    """Serve an in-memory {path: (status, headers_dict, body)} site offline.

    pages may also map a path to a string, which is served as 200 text/html.
    Returns (server, base_url). Caller shuts the server down.
    """

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            entry = pages.get(self.path)
            if entry is None:
                self.send_response(404)
                self.send_header("Content-Type", "text/html;charset=utf-8")
                self.end_headers()
                self.wfile.write(b"not found")
                return
            if isinstance(entry, str):
                status, headers, body = 200, {"Content-Type": "text/html"}, entry.encode()
            else:
                status, headers, body = entry
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:{0}".format(server.server_address[1])
    return server, base


def run_crawl(base, inventory=None, gate=None, config=None):
    """Run one Checker crawl against base with a clean shared queue."""
    check = Checker(base, config or Config(), inventory=inventory, gate=gate)
    with check.TO_PROCESS.mutex:
        check.TO_PROCESS.queue.clear()
    if inventory is not None:
        check.prime_from_inventory()
    check.TO_PROCESS.put(
        {"parent": base, "url": base, "depth": 0, "tag": "", "attr": ""}
    )
    check.run()
    check.pool.shutdown()
    return check


class TestCrawlInventory(unittest.TestCase):
    """End-to-end crawls against localhost, asserting inventory contents."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.inv_path = os.path.join(self.tmpdir, "inventory.jsonl")
        self.pages = {
            "/": (
                200,
                {"Content-Type": "text/html; charset=utf-8"},
                b'<a href="page2.html">p2</a>'
                b'<a href="page2.html">p2 dup</a>'
                b'<img src="logo.png">'
                b'<a href="missing.html">broken</a>',
            ),
            "/page2.html": (
                200,
                {"Content-Type": "text/html"},
                b'<a href="/">home</a>',
            ),
            "/logo.png": (200, {"Content-Type": "image/png"}, b"PNGDATA"),
        }
        self.server, self.base = start_fixture_server(self.pages)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _load_rows(self):
        with open(self.inv_path, "r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def test_full_inventory_rows_and_fields(self):
        inv = InventoryStore(self.inv_path)
        inv.open_for_writing()
        check = run_crawl(self.base + "/", inventory=inv)
        inv.rewrite()
        inv.close()

        rows = {r["url"]: r for r in self._load_rows()}
        # Seed, page2 (deduped despite two identical links), logo, missing.
        self.assertEqual(
            set(rows),
            {
                self.base + "/",
                self.base + "/page2.html",
                self.base + "/logo.png",
                self.base + "/missing.html",
            },
        )
        for row in rows.values():
            self.assertEqual(list(row.keys()), INVENTORY_FIELDS)

        seed = rows[self.base + "/"]
        self.assertEqual(seed["parent"], seed["url"])  # seed parent is itself
        self.assertEqual(seed["depth"], 0)
        self.assertEqual(seed["tag"], "")
        self.assertEqual(seed["attr"], "")

        page2 = rows[self.base + "/page2.html"]
        self.assertEqual(page2["parent"], self.base + "/")
        self.assertEqual(page2["depth"], 1)
        self.assertEqual(page2["tag"], "a")
        self.assertEqual(page2["attr"], "href")

        logo = rows[self.base + "/logo.png"]
        self.assertEqual(logo["tag"], "img")
        self.assertEqual(logo["attr"], "src")
        self.assertEqual(logo["content_type"], "image/png")
        self.assertEqual(logo["bytes"], 7)

        # A 404 is still a response: status recorded, error stays null.
        missing = rows[self.base + "/missing.html"]
        self.assertEqual(missing["status"], 404)
        self.assertIsNone(missing["error"])

        # Old YAML report behavior is intact alongside the inventory.
        self.assertEqual(len(check.broken), 1)
        self.assertEqual(check.broken[0]["code"], 404)

    def test_normalization_dedup_across_casing_and_default_port(self):
        # No real requests: a stubbed fetch records which distinct keys were
        # probed. The three links normalize to the same key, so only one row.
        inv = InventoryStore(self.inv_path)
        inv.open_for_writing()
        check = Checker(self.base + "/", Config(), inventory=inv)
        with check.TO_PROCESS.mutex:
            check.TO_PROCESS.queue.clear()
        probed = []

        def fake_load(page, timeout):
            probed.append(normalize_url(page["url"]))
            row = check._make_row(page)
            row["status"] = 200
            row["content_type"] = "text/html"
            row["checked_at"] = "2026-01-01T00:00:00+00:00"
            check._record_row(row)
            return {
                "url": page["url"],
                "parent": page["parent"],
                "data": "",
                "valid_content_type": False,
            }

        check.load_url = fake_load
        port = self.server.server_address[1]
        variants = [
            "http://127.0.0.1:{0}/x".format(port),
            "http://127.0.0.1:{0}/X".format(port),  # path case differs: distinct
            "http://127.0.0.1:{0}/x?y=1".format(port),  # query differs: distinct
        ]
        for link in variants:
            check.TO_PROCESS.put(
                {"parent": self.base + "/", "url": link, "depth": 1,
                 "tag": "a", "attr": "href"}
            )
        check.run()
        check.pool.shutdown()
        inv.rewrite()
        inv.close()

        self.assertEqual(len(probed), 3)
        keys = [normalize_url(r["url"]) for r in self._load_rows()]
        self.assertEqual(len(keys), len(set(keys)))

        # And a case/port-only variant of an existing key collapses to one row.
        inv2 = InventoryStore(os.path.join(self.tmpdir, "inv2.jsonl"))
        inv2.open_for_writing()
        check2 = Checker(self.base + "/", Config(), inventory=inv2)
        with check2.TO_PROCESS.mutex:
            check2.TO_PROCESS.queue.clear()
        seen = []

        def fake_load2(page, timeout):
            seen.append(page["url"])
            row = check2._make_row(page)
            row["status"] = 200
            row["checked_at"] = "2026-01-01T00:00:00+00:00"
            check2._record_row(row)
            return None

        check2.load_url = fake_load2
        same_key = [
            "http://127.0.0.1:{0}/a".format(port),
            "http://127.0.0.1:{0}/a#frag".format(port),
            "http://127.0.0.1:{0}/./a".format(port),
        ]
        for link in same_key:
            check2.TO_PROCESS.put(
                {"parent": self.base + "/", "url": link, "depth": 1,
                 "tag": "a", "attr": "href"}
            )
        check2.run()
        check2.pool.shutdown()
        inv2.close()
        self.assertEqual(len(seen), 1)

    def test_resume_skips_successful_links(self):
        inv = InventoryStore(self.inv_path)
        inv.open_for_writing()
        first = run_crawl(self.base + "/", inventory=inv)
        inv.close()
        self.assertEqual(first.skipped, 0)
        self.assertEqual(first.checked, 4)

        inv2 = InventoryStore(self.inv_path)
        inv2.load()
        inv2.open_for_writing()
        second = run_crawl(self.base + "/", inventory=inv2)
        inv2.rewrite()
        inv2.close()

        self.assertEqual(second.checked, 0)
        self.assertEqual(second.skipped, 4)
        # Still exactly one line per link after the resume run.
        self.assertEqual(len(self._load_rows()), 4)

    def test_refresh_reprobes_and_overwrites_rows(self):
        inv = InventoryStore(self.inv_path)
        inv.open_for_writing()
        run_crawl(self.base + "/", inventory=inv)
        inv.close()
        before = {r["url"]: r["checked_at"] for r in self._load_rows()}

        inv2 = InventoryStore(self.inv_path, refresh=True)
        inv2.load()
        inv2.open_for_writing()
        check = run_crawl(self.base + "/", inventory=inv2)
        inv2.rewrite()
        inv2.close()

        self.assertEqual(check.skipped, 0)
        self.assertEqual(check.checked, 4)
        rows = self._load_rows()
        self.assertEqual(len(rows), 4)  # overwritten, not duplicated

    def test_failed_probe_still_gets_a_row(self):
        inv = InventoryStore(self.inv_path)
        inv.open_for_writing()
        # Nothing listens here: connection refused, no response.
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        dead_port = sock.getsockname()[1]
        sock.close()
        dead = "http://127.0.0.1:{0}/".format(dead_port)
        quick = Config()
        quick.timeout = 2
        check = run_crawl(dead, inventory=inv, config=quick)
        inv.close()

        rows = self._load_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], 0)
        self.assertEqual(rows[0]["error"], "connection_refused")
        # And the failure still feeds the classic broken-link report.
        self.assertEqual(len(check.broken), 1)
        self.assertEqual(check.broken[0]["code"], 0)


class TestCliAndSummary(unittest.TestCase):
    """Exercise the real command line end to end, fully offline."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.inv_path = os.path.join(self.tmpdir, "inventory.jsonl")
        self.summary_path = os.path.join(self.tmpdir, "summary.json")
        pages = {
            "/": (
                200,
                {"Content-Type": "text/html"},
                b'<a href="a">a</a><a href="b">b</a><a href="missing">x</a>',
            ),
            "/a": (200, {"Content-Type": "text/plain"}, b"a-body"),
            "/b": (200, {"Content-Type": "text/plain"}, b"b-body"),
        }
        self.server, self.base = start_fixture_server(pages)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _run_cli(self, *extra):
        env = dict(os.environ)
        # Keep proxy environment from intercepting localhost in CI boxes.
        env["NO_PROXY"] = "127.0.0.1,localhost"
        env["no_proxy"] = "127.0.0.1,localhost"
        return subprocess.run(
            [sys.executable, HYDRA, self.base + "/"] + list(extra),
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    def _read_inventory(self):
        with open(self.inv_path, "r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def test_no_new_flags_keeps_legacy_behavior(self):
        result = self._run_cli()
        self.assertEqual(result.returncode, 1)  # one broken link, old exit code
        self.assertIn("title: Broken Link Report", result.stdout)
        self.assertIn("broken: 1", result.stdout)
        self.assertFalse(os.path.exists(self.inv_path))
        self.assertFalse(os.path.exists(self.summary_path))

    def test_inventory_and_summary_reconcile(self):
        result = self._run_cli(
            "--inventory", self.inv_path, "--summary", self.summary_path
        )
        self.assertEqual(result.returncode, 1)

        rows = self._read_inventory()
        self.assertEqual(len(rows), 4)
        with open(self.summary_path, "r", encoding="utf-8") as handle:
            summary = json.load(handle)

        self.assertEqual(summary["discovered"], len(rows))
        self.assertEqual(
            summary["probed"] + summary["skipped"], summary["discovered"]
        )
        self.assertEqual(
            summary["successful"] + summary["failed"], summary["discovered"]
        )
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["seed_url"], self.base + "/")
        self.assertTrue(summary["run_id"])
        self.assertTrue(summary["started_at"].endswith("+00:00"))

        # Status distribution counts must match the rows one for one.
        counted = {}
        for row in rows:
            counted[str(row["status"])] = counted.get(str(row["status"]), 0) + 1
        self.assertEqual(summary["status_distribution"], counted)
        self.assertEqual(summary["error_distribution"], {})

    def test_resume_run_skips_and_summary_reflects_it(self):
        self._run_cli("--inventory", self.inv_path, "--summary", self.summary_path)
        result = self._run_cli(
            "--inventory", self.inv_path, "--summary", self.summary_path
        )
        self.assertEqual(result.returncode, 0)  # nothing newly broken this run
        with open(self.summary_path, "r", encoding="utf-8") as handle:
            summary = json.load(handle)
        self.assertEqual(summary["probed"], 0)
        self.assertEqual(summary["skipped"], 4)
        self.assertEqual(len(self._read_inventory()), 4)

    def test_refresh_reprobes_all(self):
        self._run_cli("--inventory", self.inv_path)
        result = self._run_cli(
            "--inventory", self.inv_path,
            "--summary", self.summary_path, "--refresh",
        )
        self.assertEqual(result.returncode, 1)
        with open(self.summary_path, "r", encoding="utf-8") as handle:
            summary = json.load(handle)
        self.assertEqual(summary["probed"], 4)
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(len(self._read_inventory()), 4)

    def test_summary_without_inventory_is_rejected(self):
        result = self._run_cli("--summary", self.summary_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--summary requires --inventory", result.stdout)

    def test_per_host_interval_slows_single_host_crawl(self):
        # Four pages all on one host; a 0.2s interval must space them out.
        start = time.monotonic()
        result = self._run_cli(
            "--inventory", self.inv_path, "--per-host-interval", "0.2"
        )
        elapsed = time.monotonic() - start
        self.assertEqual(result.returncode, 1)
        self.assertGreaterEqual(elapsed, 0.6)  # 4 requests, 3 gaps
        self.assertEqual(len(self._read_inventory()), 4)

    def test_max_per_host_caps_concurrency(self):
        # Cap of 1 against a server whose responses sleep: with several pages
        # the crawl must still complete, having serialized host requests.
        slow_pages = {
            "/": (
                200,
                {"Content-Type": "text/html"},
                b'<a href="s1">1</a><a href="s2">2</a><a href="s3">3</a>',
            ),
        }
        for name in ("/s1", "/s2", "/s3"):
            slow_pages[name] = (200, {"Content-Type": "text/plain"}, b"x")

        gate = HostGate(max_per_host=1)
        inv = InventoryStore(os.path.join(self.tmpdir, "cap.jsonl"))
        inv.open_for_writing()

        original_load = Checker.load_url

        def instrumented_load(self_, page, timeout):
            host = extract_domain(page["url"])
            gate.acquire(host)
            try:
                in_flight = gate._hosts[host]["in_flight"]
                self.assertLessEqual(in_flight, 1)
                time.sleep(0.05)
                return original_load(self_, page, timeout)
            finally:
                gate.release(host)

        server, base = start_fixture_server(slow_pages)
        try:
            # Gate lives only in the instrumented fetch so we can observe the
            # in-flight count at request start.
            check = Checker(base + "/", Config(), inventory=inv)
            check.load_url = instrumented_load.__get__(check, Checker)
            with check.TO_PROCESS.mutex:
                check.TO_PROCESS.queue.clear()
            check.TO_PROCESS.put(
                {"parent": base + "/", "url": base + "/",
                 "depth": 0, "tag": "", "attr": ""}
            )
            check.run()
            check.pool.shutdown()
        finally:
            server.shutdown()
            server.server_close()
            inv.close()
        self.assertEqual(len(inv.rows()), 4)

    def test_interrupted_run_leaves_parseable_lines_and_no_summary(self):
        # A server that sleeps on each response so the crawl is still running
        # when we send SIGINT.
        class SlowHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                time.sleep(0.3)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<p>ok</p>")

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SlowHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:{0}/".format(server.server_address[1])
        env = dict(os.environ)
        env["NO_PROXY"] = "127.0.0.1,localhost"
        env["no_proxy"] = "127.0.0.1,localhost"
        try:
            proc = subprocess.Popen(
                [sys.executable, HYDRA, base,
                 "--inventory", self.inv_path, "--summary", self.summary_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
            time.sleep(0.6)
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=10)
            self.assertEqual(proc.returncode, 130)
        finally:
            server.shutdown()
            server.server_close()

        # Every persisted line is a complete JSON object; no half lines.
        rows = self._read_inventory()
        self.assertGreaterEqual(len(rows), 1)
        for row in rows:
            self.assertIn("url", row)
            self.assertIn("checked_at", row)
        # Summary is only written after a complete run.
        self.assertFalse(os.path.exists(self.summary_path))


if __name__ == "__main__":
    unittest.main()
