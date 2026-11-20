"""Command-line entry point shared by the installed script and python -m."""

import argparse
import json
import logging
import os
import sqlite3
import sys
import tempfile
from collections.abc import Sequence
from contextlib import closing
from pathlib import Path

from . import __version__
from .comparison import compare
from .config import NetworkSettings, data_directory, default_database
from .http import HttpClient
from .models import Investigation, coverage_status
from .orchestration import COLLECTORS, investigate, select_collectors
from .rate_limit import RateLedger
from .reporting import CHANGE_LABELS, html_report, json_report
from .storage import Repository
from .validation import normalize_domain


def _domain(value: str) -> str:
    try:
        return normalize_domain(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db",
        type=Path,
        default=argparse.SUPPRESS,
        metavar="PATH",
        help="SQLite history file (default from OSINTSCOPE_DB or user data directory)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="show collection diagnostics on stderr",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osintscope",
        description="Investigate domain infrastructure using public third-party records.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    _options(parser)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("scan", "collect and store a new investigation"),
        ("history", "list stored investigations for a domain"),
        ("diff", "compare the two latest investigations"),
        ("report", "export a stored investigation and its comparison"),
        ("sources", "list the public data sources"),
    ):
        sub = commands.add_parser(name, help=help_text, description=help_text.capitalize())
        _options(sub)
        if name != "sources":
            sub.add_argument("domain", type=_domain)
        if name == "scan":
            sub.add_argument(
                "--source",
                action="append",
                choices=[c.key for c in COLLECTORS],
                help="use this source and its prerequisites (repeatable; default all)",
            )
            sub.add_argument(
                "--timeout",
                type=float,
                default=10,
                metavar="SECONDS",
                help="socket timeout per request (default 10, maximum 60)",
            )
            sub.add_argument(
                "--retries",
                type=int,
                default=1,
                choices=range(4),
                help="retries for transient failures (default 1)",
            )
        if name == "diff":
            sub.add_argument("--format", choices=("text", "json"), default="text")
        if name == "report":
            sub.add_argument("--format", choices=("html", "json"), default="html")
            sub.add_argument(
                "--scan-id", type=int, help="report a specific investigation for the domain"
            )
            sub.add_argument("-o", "--output", type=Path, help="write to a file (default stdout)")
    return parser


def _write_report(output: Path | None, content: str, database: Path) -> None:
    if output is None:
        # Windows pipes can otherwise select a legacy console code page.
        stream = getattr(sys.stdout, "buffer", None)
        if stream is None:
            print(content)
        else:
            stream.write((content + "\n").encode("utf-8"))
        return
    output = output.expanduser()
    resolved = output.resolve()
    protected = [database.resolve(), (data_directory() / "requests.sqlite3").resolve()]
    if any(
        resolved == Path(str(path) + suffix)
        for path in protected
        for suffix in ("", "-wal", "-shm", "-journal")
    ):
        raise ValueError("Choose a report path separate from the history and request databases.")
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = tempfile.NamedTemporaryFile(
        dir=output.parent, encoding="utf-8", mode="w", delete=False, prefix=".osintscope-"
    )
    path = Path(temp.name)
    try:
        with temp:
            temp.write(content)
            temp.write("\n")
        os.replace(path, output)
    finally:
        path.unlink(missing_ok=True)


def _report_pair(repo: Repository, domain: str, scan_id: int | None) -> list[Investigation]:
    if scan_id is None:
        return repo.latest(domain, 2)
    scan = repo.get(scan_id)
    if scan is None or scan.domain != domain:
        raise ValueError(f"No investigation #{scan_id} for {domain}.")
    history = repo.history(domain)
    index = next(i for i, item in enumerate(history) if item["id"] == scan_id)
    if index + 1 == len(history):
        return [scan]
    previous = repo.get(history[index + 1]["id"])
    return [scan, previous] if previous else [scan]


def _run(args: argparse.Namespace) -> int:
    if args.command == "sources":
        for source in COLLECTORS:
            print(
                f"{source.key:<12} {source.name}\n             {source.description}\n             {source.homepage}"
            )
        return 0

    database = getattr(args, "db", default_database()).expanduser()
    settings = NetworkSettings(args.timeout, args.retries) if args.command == "scan" else None
    with Repository(database) as repo:
        if args.command == "scan":
            assert settings is not None
            collectors = select_collectors(args.source)
            with closing(RateLedger(data_directory() / "requests.sqlite3")) as ledger:
                scan = investigate(
                    args.domain, HttpClient(args.domain, settings, ledger), collectors
                )
            scan_id = repo.save(scan)
            status = coverage_status(scan.coverage)
            print(f"Investigation #{scan_id}  {scan.domain}  {status}")
            print(f"{len(scan.observations)} observations, {len(scan.relationships)} relationships")
            for item in scan.coverage:
                print(f"  {item.key:<12} {item.status:<9} {item.message}".rstrip())
            return {"complete": 0, "partial": 3, "failed": 1}[status]
        if args.command == "history":
            rows = repo.history(args.domain)
            if not rows:
                print(f"No stored investigations for {args.domain}.")
                return 0
            print("ID     STARTED (UTC)                        STATUS    OBSERVATIONS")
            for row in rows:
                print(
                    f"{row['id']:<6} {row['started_at']:<36} {row['status']:<9} {row['observations']}"
                )
            return 0

        scans = _report_pair(repo, args.domain, getattr(args, "scan_id", None))
        if not scans:
            raise ValueError(f"No stored investigations for {args.domain}.")
        current = scans[0]
        previous = scans[1] if len(scans) > 1 else None
        if args.command == "report":
            render = html_report if args.format == "html" else json_report
            _write_report(args.output, render(current, previous), database)
            return 0
        if previous is None:
            raise ValueError(f"Two stored investigations are required to compare {args.domain}.")
        changes = compare(previous, current)
        if args.format == "json":
            print(json.dumps(changes, indent=2))
        else:
            print(f"{args.domain}  #{previous.id} -> #{current.id}")
            for key, label in CHANGE_LABELS.items():
                print(f"{label} ({len(changes[key])})")
                for change in changes[key]:
                    print(
                        f"  {change['rrtype'] or change['kind']}  {change['subject']}  {change['value']}"
                        f"  [{', '.join(change['sources'])}]  {change['reason']}"
                    )
            for warning in changes["warnings"]:
                print(f"Warning: {warning}")
        return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
        format="%(levelname)s %(name)s  %(message)s",
    )
    try:
        return _run(args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"osintscope: {exc}", file=sys.stderr)
        return 1
