# OSINTScope

OSINTScope is a Python CLI for investigating public domain infrastructure. Each scan saves an attributable snapshot in SQLite. Compare snapshots to see which DNS answers, certificate names, registration facts, and routing associations appeared in the available records.

The collectors read existing third-party datasets and registry records. A scan sends the query to the selected providers. It performs no DNS resolution of the target, HTTP requests to discovered hosts, TLS handshakes with them, or submissions to scanning services. The five built-in sources work without paid keys or AI services.

## Install

From the project directory containing `pyproject.toml`, use Python 3.11 or later. On Kali or Debian, install the virtual environment package if needed.

```bash
sudo apt install python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
osintscope --version
```

On Windows, run these commands in PowerShell. Skip the first command if the project already has a virtual environment.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m osintscope sources
```

For the examples below, use `.\.venv\Scripts\osintscope.exe` when the environment is inactive.

Use the project’s `.venv` interpreter in VS Code. The only runtime dependency outside Python's standard library is `idna`, used to normalize internationalized names.

## Run an investigation

```bash
osintscope sources
osintscope scan example.com
osintscope history example.com
osintscope report example.com --format html -o reports/example.html
osintscope report example.com --format json -o reports/example.json
```

Run a second scan to compare two snapshots. Using the same sources makes their coverage easier to compare.

```bash
python -m osintscope scan example.com
osintscope diff example.com
osintscope diff example.com --format json
```

Select a smaller set of providers with repeated `--source` arguments. ASN enrichment includes its passive DNS prerequisite automatically.

```bash
osintscope scan example.com --source rdap --source ct --timeout 8 --retries 1
osintscope scan example.com --source asn
osintscope report example.com --scan-id 1 --format json
osintscope --db ./case.sqlite3 history example.com
```

Reports default to standard output. `-o` atomically writes or replaces the named report file. HTML reports work offline and link back to evidence. JSON includes a schema version, collection summary, observations, coverage, relationships, and comparison with the preceding investigation. The first snapshot has a null comparison.

## Source coverage

| Source key | Evidence and boundaries |
| --- | --- |
| `rdap` | Uses IANA bootstrap data to locate the registry for the exact name. Saves technical registration dates, statuses, registrar identifiers and nameservers. Some registries omit fields or decline access, and hostnames below a registered domain may have no RDAP object. [IANA bootstrap registry](https://www.iana.org/assignments/rdap-dns) |
| `pdns` | Requests up to 1,000 public archive rows for the queried name and retains matching A, AAAA, CNAME, MX and NS answers. Public addresses and provider sighting dates are kept where available. Archive coverage varies by name and record type. [mnemonic public API](https://docs.mnemonic.no/service-integration-guides/passivedns/docs/public/01-public_api.html) |
| `asn` | Looks up the covering prefix and all reported origin ASNs for up to five distinct public IPs from passive DNS. RIPEstat describes its routing view at query time. [RIPEstat Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info.html) |
| `ct` | Queries the crt.sh certificate identity index. Retains matching certificate IDs, in-scope names and available dates. Explicit subdomain names and wildcard certificate patterns are kept distinct. [crt.sh](https://crt.sh/) |
| `technology` | Reads up to 20 existing public urlscan search results and extracts the first product from the recorded HTTP Server field when present. Provider search windows, result limits, and missing scan timestamps appear in coverage notes. [urlscan Search API](https://urlscan.io/docs/search/) |

Public access is subject to each provider's terms. The shared transport identifies the client, verifies HTTPS, rejects redirects, bounds response sizes to 8 MiB, and applies a socket timeout. It retries transient failures within the selected retry budget (default one retry). Access denials and quota errors are reported. A local SQLite request ledger spaces requests by hostname across invocations. For mnemonic it enforces at least 6.1 seconds between attempts and at most 1,000 attempts in a rolling 24 hours. Provider limits can be shared with other clients on the same network. Long server cooldowns are recorded for later invocations. Consult RIPE NCC for its bulk and commercial-use conditions. [mnemonic access limits](https://docs.mnemonic.no/service-integration-guides/passivedns/docs/public/01-public_api.html) · [RIPEstat access policy](https://stat.ripe.net/docs/data-api/ripestat-data-api)

## Interpret the evidence

Every observation records a subject, value, source, reference and UTC collection timestamp. Source-specific details hold historical timestamps, DNS types, certificate names, or BGP prefixes. The database stores selected technical fields and omits registration contact records, raw responses and full page URLs.

- **Observed relationships** have high confidence that a cited source reported the association. An archived name or address may have changed since its provider last saw it.
- **Inferred relationships** have medium confidence when a hostname and ASN can be joined through a public IP. The reason identifies the intermediary IPs and supporting sources. Hosting, ownership, and timing require independent evidence.
- **Newly observed** means the current snapshot contains a fact absent from an earlier comparable response. **No longer observed** means a later comparable source response omitted a previously reported fact.
- **Uncertain changes** identify missing, failed, or partial coverage. Current sources supply no explicit removal events, so archive omissions never populate **confirmed removals**. Routine collection timestamp changes do not create new facts.

Coverage applies to the configured lookup. `complete` means the collector finished that lookup, `partial` records a limitation, and `failed` records a source failure. A successful zero-match response can be complete. Other collectors can still return usable evidence when a provider times out, throttles, or changes its response format.

## Storage and exit codes

Linux defaults to `$XDG_DATA_HOME/osintscope/history.sqlite3` or `~/.local/share/osintscope/history.sqlite3`. Windows uses `%LOCALAPPDATA%\osintscope\history.sqlite3`. Set `OSINTSCOPE_DB` or pass `--db PATH` to choose the history file. The rate ledger stays in the per-user data directory across case databases. History, diff and report work from local records without network access.

| Exit | Meaning |
| --- | --- |
| 0 | Successful command, including a complete scan |
| 1 | Failed scan or command error, such as an unavailable baseline |
| 2 | Command-line syntax error |
| 3 | Partial scan saved successfully |
| 130 | Interrupted by the user |

Use `--verbose` for transport and collector diagnostics on stderr. A completed collection attempt is saved even if every selected provider failed.

## Architecture and development

| Module | Responsibility |
| --- | --- |
| `cli.py`, `config.py`, `validation.py` | Command handling, paths, network settings and domain normalization |
| `collectors/`, `http.py`, `rate_limit.py`, `errors.py` | Source-specific parsing, HTTPS, backoff, quotas and fetch errors |
| `models.py`, `orchestration.py` | Typed records, collector registration, prerequisites and failure isolation |
| `analysis.py`, `comparison.py` | Evidence deduplication, relationship derivation and source-aware changes |
| `storage.py`, `reporting.py` | Transactional SQLite snapshots, schema versioning and exports |

To add a provider, implement the `Collector` protocol from `orchestration.py`. Give it a source key and a `collect(domain, client, prior)` method that returns observations and coverage. Declare prerequisite source keys with `requires` when necessary, register the collector in `COLLECTORS`, and add its fixed HTTPS provider hostname to the transport policy. Use fixture responses to cover successful, empty, partial and failed collection.

Run the offline suite from the project directory.

```bash
python -m unittest discover -v
```

Released under the [MIT license](LICENSE).
