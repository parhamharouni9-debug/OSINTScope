"""Compare observations using each provider's coverage in both investigations."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import Investigation, Observation

FactKey = tuple[str, str, str, str]


def _index(observations: list[Observation]) -> dict[FactKey, set[str]]:
    facts: dict[FactKey, set[str]] = defaultdict(set)
    for item in observations:
        rrtype = item.details.get("rrtype", "") if item.kind == "dns" else ""
        facts[item.kind, item.subject, item.value, rrtype].add(item.source)
    return facts


def _asn_lookup_addresses(scan: Investigation) -> set[str]:
    # The built-in enrichment runs after passive DNS. A complete run queried
    # every public address it supplied, including ones with an empty result.
    addresses = {
        o.value
        for o in scan.observations
        if o.source == "pdns"
        and (o.subject == scan.domain or o.subject.endswith("." + scan.domain))
        and (o.kind == "ip" or (o.kind == "dns" and o.details.get("rrtype") in ("A", "AAAA")))
    }
    addresses.update(o.subject for o in scan.observations if o.kind == "asn" and o.source == "asn")
    return addresses


def _complete_sources(
    key: FactKey,
    sources: set[str],
    statuses: dict[str, str],
    asn_addresses: set[str],
) -> set[str]:
    complete = {source for source in sources if statuses.get(source) == "complete"}
    if key[0] == "asn" and key[1] not in asn_addresses:
        complete.discard("asn")
    return complete


def _change(key: FactKey, sources: set[str], reason: str) -> dict[str, Any]:
    kind, subject, value, rrtype = key
    return {
        "kind": kind,
        "subject": subject,
        "value": value,
        "rrtype": rrtype or None,
        "sources": sorted(sources),
        "reason": reason,
    }


def compare(previous: Investigation, current: Investigation) -> dict[str, Any]:
    """A successful response describes the provider's view at collection time."""
    if previous.domain != current.domain:
        raise ValueError("Both investigations must cover the same domain.")
    before = _index(previous.observations)
    after = _index(current.observations)
    prior_status = {item.key: item.status for item in previous.coverage}
    later_status = {item.key: item.status for item in current.coverage}
    prior_addresses = _asn_lookup_addresses(previous)
    later_addresses = _asn_lookup_addresses(current)
    added: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    warnings = []
    for key in sorted(after.keys() - before.keys()):
        sources = after[key]
        if _complete_sources(key, sources, prior_status, prior_addresses):
            added.append(
                _change(
                    key,
                    sources,
                    "Newly observed compared with the earlier response.",
                )
            )
        else:
            unknown.append(
                _change(
                    key,
                    sources,
                    "Observed now. The earlier investigation lacks comparable source coverage for this record.",
                )
            )
    for key in sorted(before.keys() - after.keys()):
        sources = before[key]
        if _complete_sources(key, sources, later_status, later_addresses) == sources:
            missing.append(
                _change(
                    key,
                    sources,
                    "Previously observed. The later responses omitted it without evidence of removal.",
                )
            )
        else:
            unknown.append(
                _change(
                    key,
                    sources,
                    "Previously observed. The later investigation lacks comparable source coverage for this record.",
                )
            )
    for label, scan in (("Earlier", previous), ("Later", current)):
        for coverage in sorted(scan.coverage, key=lambda item: item.key):
            if coverage.status != "complete":
                message = f" ({coverage.message})" if coverage.message else ""
                warnings.append(f"{label} {coverage.key} coverage was {coverage.status}{message}.")
    for source in sorted(prior_status.keys() - later_status.keys()):
        warnings.append(f"The later investigation has no coverage record for {source}.")
    for source in sorted(later_status.keys() - prior_status.keys()):
        warnings.append(f"The earlier investigation has no coverage record for {source}.")
    if any(item["kind"] == "asn" and "asn" in item["sources"] for item in unknown):
        warnings.append(
            "RIPEstat comparisons require coverage for the same IP in both investigations."
        )
    if missing:
        warnings.append("Source responses can change as public archives update or age out records.")
    return {
        "domain": current.domain,
        "previous_id": previous.id,
        "current_id": current.id,
        "added": added,
        "not_observed": missing,
        "unknown": unknown,
        "removed": [],
        "warnings": warnings,
    }
