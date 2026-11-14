# Hydra: multithreaded site-crawling link checker in Python

![Tests status badge](https://github.com/victoriadrake/hydra-link-checker/workflows/test/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)

A Python program that ~~crawls~~ slithers 🐍 a website for links and prints a YAML report of broken links.

## Requires

Python 3.9 or higher (tested through 3.12).

There are no external dependencies, Neo.

## Usage

```sh
$ python hydra.py -h
usage: hydra.py [-h] [--config CONFIG] [--inventory INVENTORY]
                [--summary SUMMARY] [--refresh]
                [--per-host-interval PER_HOST_INTERVAL]
                [--max-per-host MAX_PER_HOST]
                URL
```

Positional arguments:

- `URL`: The URL of the website to crawl. Ensure `URL` is absolute including schema, e.g. `https://example.com`.

Optional arguments:

- `-h`, `--help`: Show help message and exit
- `--config CONFIG`, `-c CONFIG`: Path to a configuration file
- `--inventory INVENTORY`: Path to the JSON-lines link inventory. One row is appended per link as soon as it is probed, so the file stays usable if a run is interrupted. Re-running with the same file resumes the crawl: links that succeeded last time are skipped without sending a request.
- `--summary SUMMARY`: Path to the JSON run summary. Overwritten on each complete run and only written once the whole crawl finishes. Requires `--inventory`.
- `--refresh`: Ignore previous inventory results and re-probe every link. Rows are overwritten in place, so each link still ends up on exactly one line.
- `--per-host-interval PER_HOST_INTERVAL`: Minimum seconds between request starts to the same host. Default `0` means no limit. Different hosts are not delayed by each other; overall concurrency remains bounded by `threads` in the config.
- `--max-per-host MAX_PER_HOST`: Maximum simultaneous requests against one host. Default `0` means no limit.

A broken links report will be output to stdout, so you may like to redirect this to a file.

The report will be [YAML](https://yaml.org/) formatted. To save the output to a file, run:

```sh
python hydra.py [URL] > [PATH/TO/FILE.yaml]
```

You can add the current date to the filename using a command substitution, such as:

```sh
python hydra.py [URL] > /path/to/$(date '+%Y_%m_%d')_report.yaml
```

To see how long Hydra takes to check your site, add `time`:

```sh
time python hydra.py [URL]
```

### Link inventory (`--inventory`)

The inventory is a [JSON Lines](https://jsonlines.org/) file: one JSON object per line, one line per unique link. It is written incrementally while the crawl runs; every line that reaches disk is complete and independently parseable, so killing the process (or losing the network) never leaves a half-written line. On the next run with the same `--inventory` path, the existing lines are merged first and the crawl picks up where it stopped.

Each line has exactly these fields, in this order:

| Field | Meaning |
| --- | --- |
| `url` | Absolute URL of the probed link. |
| `parent` | Page the link was discovered on. For the seed page this is the seed URL itself. |
| `depth` | Crawl depth starting at `0` for the seed; each discovered level adds one. |
| `tag` | HTML tag the link came from, e.g. `a`, `img`, `script`. Empty for the seed. |
| `attr` | Attribute holding the URL, e.g. `href`, `src`. Empty for the seed. |
| `status` | Final response status code. `0` when no response was ever received. |
| `content_type` | Raw `Content-Type` response header value. Empty when the header is absent. |
| `bytes` | Number of bytes actually read from the response body. |
| `redirects` | Full chain of URLs from the first redirect jump through the final landing page. An empty array when there were no redirects. |
| `elapsed_ms` | Probe duration in milliseconds. |
| `error` | Stable error category name for network-layer failures, or `null` on success / whenever a response was received. |
| `checked_at` | Probe timestamp as UTC [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601). |

Links are de-duplicated within and across runs by their normalized URL: scheme and host are case-insensitive, default ports are removed, fragments are dropped, an empty path becomes `/`, and `.`/`..` path segments are resolved. The query string is kept exactly as found and never reordered, so links that differ only in query parameters stay distinct.

The `error` field uses these stable category names — note that an HTTP status such as 404 or 500 is a *response*, so it goes in `status` with `error: null`; error categories are reserved for requests that never got a response at all:

- `timeout` — the request timed out
- `dns_error` — DNS resolution failed
- `connection_refused` — the connection was refused
- `tls_error` — the TLS handshake failed
- `too_many_redirects` — the redirect limit was exceeded
- `invalid_url` — the URL could not be parsed/normalized
- `network_error` — any other network-layer problem

### Run summary (`--summary`)

After a complete run the summary file is overwritten with a single JSON object:

| Field | Meaning |
| --- | --- |
| `run_id` | Unique id for the run. |
| `started_at` / `finished_at` | UTC ISO 8601 timestamps. |
| `seed_url` | The crawl's starting URL. |
| `discovered` | Total unique links in the inventory. |
| `probed` | Links actually requested during this run. |
| `skipped` | Links skipped because a previous run already probed them successfully. |
| `successful` | Rows whose status is in the configured `OK` list and have no error. |
| `failed` | All other rows (bad statuses and error categories). |
| `status_distribution` | Count of rows per HTTP status code (keys are strings). |
| `error_distribution` | Count of rows per error category. |

The numbers reconcile with the inventory: `discovered = probed + skipped` and `discovered = successful + failed`. The summary is not written if the run is interrupted, so it can never describe a partial crawl.

### Example: weekly resumable crawl with a dashboard-ready dataset

```sh
# First run — writes inventory.jsonl line by line and summary.json at the end.
python hydra.py https://example.com \
    --inventory ./data/inventory.jsonl \
    --summary ./data/summary.json \
    --per-host-interval 1 --max-per-host 5 \
    > ./data/broken-links.yaml

# If the network drops or you press Ctrl-C, just run the same command again:
# previously successful links are skipped, failed ones are retried.
python hydra.py https://example.com \
    --inventory ./data/inventory.jsonl \
    --summary ./data/summary.json

# Force every link to be re-checked from scratch (rows are overwritten):
python hydra.py https://example.com \
    --inventory ./data/inventory.jsonl \
    --summary ./data/summary.json --refresh
```

Running without `--inventory` (and therefore without `--summary`) behaves exactly as before: the YAML broken-link report is printed to stdout and the process exits `1` when broken links are found unless `graceful_exit` is set.

### GitHub Action

You can easily incorporate Hydra as part of an automated process using the [link-snitch](https://github.com/victoriadrake/link-snitch) action.

## Configuration

Hydra can accept an optional JSON configuration file for specific parameters, for example:

```json
{
    "OK": [
        200,
        999,
        403
    ],
    "attrs": [
        "href"
    ],
    "exclude_scheme_prefixes": [
        "tel"
    ],
    "tags": [
        "a",
        "img"
    ],
    "threads": 25,
    "timeout": 30,
    "graceful_exit": "True"
}
```

To use a configuration file, supply the filename:

```sh
python hydra.py https://example.com --config ./hydra-config.json
```

Possible settings:

- `OK` - [HTTP response codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status) to consider as a successful link check. Defaults to `[200, 999]`.
- `attrs` - Attributes of the HTML tags to check for links. Defaults to `["href", "src"]`.
- `exclude_scheme_prefixes` - Link prefixes to exclude from checking. Any link that _starts with_ one of these strings is skipped, so this works for schemes (`"tel:"`, `"javascript:"`) as well as whole domains or path prefixes. Defaults to `["tel:", "javascript:"]`.
- `tags` - HTML tags to check for links. Defaults to `["a", "link", "img", "script"]`.
- `threads` - Maximum workers to run. Defaults to `50`.
- `timeout` - Maximum seconds to wait for HTTP response. Defaults to `60`.
- `graceful_exit` - If set to `True`, and there are broken links present return `exit code 0` else return `exit code 1`.

### Excluding domains

Some sites block crawlers or rate-limit them (HTTP 429), producing noise in your
report. Because `exclude_scheme_prefixes` matches any leading substring, you can
exclude whole domains or path prefixes by listing their URL prefixes:

```json
{
    "exclude_scheme_prefixes": [
        "tel:",
        "javascript:",
        "https://twitter.com/",
        "https://www.npmjs.com/package/",
        "https://github.com/owner/repo/issues/"
    ]
}
```

## Test

Run:

```sh
python -m unittest tests/test.py
```

## Screenshots

### Passing Tests

![Passing Tests](screenshots/test-pass.png)

### Failing Tests

![Failing Tests](screenshots/test-fail.png)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
