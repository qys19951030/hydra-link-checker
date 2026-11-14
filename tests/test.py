import functools
import http.server
import json
import os
import socket
import socketserver
import ssl
import tempfile
import threading
import time
import unittest
from urllib import error

from hydra import (
    Checker,
    Config,
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


if __name__ == "__main__":
    unittest.main()
