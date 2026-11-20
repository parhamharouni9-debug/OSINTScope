"""Self-contained HTML and a versioned, lossless JSON export of a snapshot."""

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict
from html import escape
from typing import Any
from urllib.parse import urlsplit

from .comparison import compare
from .models import Investigation, coverage_status

CHANGE_LABELS = {
    "added": "Newly observed",
    "not_observed": "No longer observed",
    "unknown": "Uncertain changes",
    "removed": "Confirmed removals",
}


def report_payload(scan: Investigation, previous: Investigation | None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "summary": {
            "status": coverage_status(scan.coverage),
            "observation_count": len(scan.observations),
            "observations_by_kind": dict(
                sorted(Counter(o.kind for o in scan.observations).items())
            ),
            "relationship_count": len(scan.relationships),
            "inferred_relationship_count": sum(r.basis == "inferred" for r in scan.relationships),
        },
        "investigation": asdict(scan),
        "comparison": compare(previous, scan) if previous else None,
    }


def json_report(scan: Investigation, previous: Investigation | None = None) -> str:
    return json.dumps(report_payload(scan, previous), ensure_ascii=False, indent=2)


def _cell(value: object) -> str:
    return escape(str(value))


def _reference(url: str) -> str:
    try:
        parts = urlsplit(url)
        if parts.scheme == "https" and parts.hostname and parts.username is None:
            return (
                f'<a href="{escape(url, quote=True)}" rel="noreferrer">{_cell(parts.hostname)}</a>'
            )
    except ValueError:
        pass
    return _cell(url)


def _table(headers: tuple[str, ...], rows: Iterable[tuple[str, ...]], empty: str) -> str:
    body = "".join("<tr>" + "".join(f"<td>{v}</td>" for v in row) + "</tr>" for row in rows)
    if not body:
        return f'<p class="empty">{escape(empty)}</p>'
    head = "".join(f'<th scope="col">{escape(h)}</th>' for h in headers)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _changes(data: dict[str, Any] | None) -> str:
    if data is None:
        return '<p class="empty">First stored investigation for this domain. No earlier comparison is available.</p>'
    parts = [f"<p>Compared with investigation #{_cell(data['previous_id'])}.</p>"]
    parts.extend(f'<p class="notice">{_cell(w)}</p>' for w in data["warnings"])
    for key, label in CHANGE_LABELS.items():
        entries = data[key]
        parts.append(f"<h3>{label} ({len(entries)})</h3>")
        if entries:
            parts.append(
                _table(
                    ("Type", "Subject", "Value", "Sources", "Assessment"),
                    (
                        (
                            _cell(c["rrtype"] or c["kind"]),
                            _cell(c["subject"]),
                            _cell(c["value"]),
                            _cell(", ".join(c["sources"])),
                            _cell(c["reason"]),
                        )
                        for c in entries
                    ),
                    "",
                )
            )
    return "".join(parts)


_STYLE = """
*{box-sizing:border-box}body{margin:0;background:#f5f7f8;color:#1b3038;
font:16px/1.5 system-ui,sans-serif}main{max-width:80rem;margin:auto;padding:2rem clamp(1rem,4vw,4rem)}
header{border-top:5px solid #177567;border-bottom:1px solid #bbc9c9;padding:1.25rem 0}
h1{font-size:clamp(1.8rem,4vw,3rem);line-height:1.15;margin:.35rem 0;overflow-wrap:anywhere}
h2{margin:2rem 0 .5rem;font-size:1.4rem}h3{margin:1.1rem 0 .35rem;font-size:1.02rem}
p{margin:.45rem 0}.meta,.empty{color:#4f6269}.summary{color:#104f47;font-weight:600}
.scroll{overflow-x:auto;background:white;border:1px solid #d0dbdc;border-radius:4px}
table{border-collapse:collapse;width:100%;font-size:.9rem}td,th{padding:.65rem .8rem;text-align:left;
vertical-align:top;border-bottom:1px solid #dce4e5;overflow-wrap:anywhere}th{background:#e5eeec}
td ul{margin:0;padding-left:1em}a{color:#075d68}.notice{border-left:3px solid #976823;padding-left:.7rem}
@media print{body{background:white}main{max-width:none;padding:0}.scroll{overflow:visible}
thead{display:table-header-group}tr{break-inside:avoid}h2,h3{break-after:avoid}}
"""


def html_report(scan: Investigation, previous: Investigation | None = None) -> str:
    domain = _cell(scan.domain)
    coverage = _table(
        ("Source", "Coverage", "Collection notes"),
        ((_cell(c.key), _cell(c.status), _cell(c.message)) for c in scan.coverage),
        "No source coverage recorded.",
    )
    evidence = _table(
        ("Type", "Subject", "Value", "Source", "Collected (UTC)", "Details"),
        (
            (
                _cell(o.kind),
                _cell(o.subject),
                _cell(o.value),
                _cell(o.source) + " · " + _reference(o.reference),
                _cell(o.observed_at),
                _cell(json.dumps(o.details, ensure_ascii=False, sort_keys=True))
                if o.details
                else "",
            )
            for o in scan.observations
        ),
        "No observations were collected.",
    )
    edges = _table(
        ("Subject", "Relationship", "Object", "Basis", "Confidence", "Reason", "Sources"),
        (
            (
                _cell(r.subject),
                _cell(r.predicate.replace("_", " ")),
                _cell(r.object),
                _cell(r.basis),
                _cell(r.confidence),
                _cell(r.reason),
                _cell(", ".join(r.sources)),
            )
            for r in scan.relationships
        ),
        "No relationships were derived.",
    )
    status = coverage_status(scan.coverage)
    notice = ""
    if status != "complete":
        notice = '<p class="notice">Source coverage is incomplete. See the collection notes before interpreting gaps.</p>'
    changes = _changes(compare(previous, scan) if previous else None)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'">
<title>{domain} — OSINTScope investigation</title><style>{_STYLE}</style></head>
<body><main><header><div>OSINTScope &nbsp;/&nbsp; Investigation #{_cell(scan.id)}</div><h1>{domain}</h1>
<p class="meta">Started {_cell(scan.started_at)}<br>Finished {_cell(scan.finished_at)}</p></header>
<section><h2>Investigation summary</h2>
<p class="summary">{status.title()} coverage · {len(scan.observations)} observations · {len(scan.relationships)} relationships</p>
<p>Evidence describes public source records at collection time. Provider timestamps appear with each observation when available.</p>{notice}</section>
<section><h2>Source coverage</h2>{coverage}</section>
<section><h2>Changes since the previous investigation</h2>{changes}</section>
<section><h2>Relationships</h2>{edges}</section>
<section><h2>Evidence</h2>{evidence}</section></main></body></html>"""
