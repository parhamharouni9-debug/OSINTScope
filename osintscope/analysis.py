"""Correlate source observations while retaining the evidence behind each edge."""

from __future__ import annotations

import json
from collections import defaultdict

from .models import Observation, Relationship


def _evidence_key(item: Observation) -> tuple[str, ...]:
    return (
        item.kind,
        item.subject,
        item.value,
        item.source,
        item.reference,
        json.dumps(item.details, ensure_ascii=False, sort_keys=True),
    )


def _dns_host(value: str) -> str:
    """An MX archive may include the preference; a null MX has no host."""
    parts = value.split()
    return parts[-1].rstrip(".") if parts else ""


def analyze(
    domain: str,
    observations: list[Observation],
) -> tuple[list[Observation], list[Relationship]]:
    """Collapse identical evidence and derive edges from the same investigation."""
    unique: dict[tuple[str, ...], Observation] = {}
    for item in observations:
        key = _evidence_key(item)
        if key not in unique or item.observed_at < unique[key].observed_at:
            unique[key] = item
    facts = [unique[key] for key in sorted(unique)]
    edges: dict[tuple[str, str, str, str, str, str], set[str]] = defaultdict(set)
    addresses: dict[tuple[str, str], set[str]] = defaultdict(set)
    networks: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    def observed(item: Observation, predicate: str, target: str, reason: str) -> None:
        if target:
            edge = (item.subject, predicate, target, "observed", "high", reason)
            edges[edge].add(item.source)

    for item in facts:
        record_type = item.details.get("rrtype") if item.kind == "dns" else None
        if item.kind == "ip" or record_type in ("A", "AAAA"):
            observed(
                item,
                "observed_address",
                item.value,
                "The source associated the hostname with this IP.",
            )
            addresses[item.subject, item.value].add(item.source)
        elif item.kind == "nameserver" or record_type == "NS":
            observed(
                item,
                "observed_nameserver",
                item.value,
                "The source reported this nameserver.",
            )
        elif record_type == "MX":
            observed(
                item,
                "observed_mail_exchanger",
                _dns_host(item.value),
                "The archive recorded this MX host.",
            )
        elif record_type == "CNAME":
            observed(
                item,
                "observed_alias_target",
                item.value,
                "The archive recorded this CNAME target.",
            )
        elif item.kind == "asn":
            observed(
                item,
                "observed_origin_as",
                item.value,
                "The source reported this route origin for the IP.",
            )
            networks[item.subject][item.value].add(item.source)
        elif item.kind == "subdomain" and item.value.endswith("." + domain):
            observed(
                item,
                "observed_subdomain",
                item.value,
                "The source listed this name under the domain.",
            )
        elif item.kind == "technology":
            observed(
                item,
                "reported_technology",
                item.value,
                "The archived page metadata reported this technology.",
            )
        elif item.kind == "certificate":
            observed(
                item,
                "observed_certificate",
                item.value,
                "The certificate index returned this entry for the domain.",
            )
            for name in item.details.get("names", ()):
                if name == domain or name.endswith("." + domain):
                    edge = (
                        item.value,
                        "lists_name",
                        name,
                        "observed",
                        "high",
                        "The certificate index listed this name for this entry.",
                    )
                    edges[edge].add(item.source)

    routes: dict[tuple[str, str], set[str]] = defaultdict(set)
    route_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    for (hostname, address), address_sources in addresses.items():
        for network, network_sources in networks.get(address, {}).items():
            routes[hostname, network].add(address)
            route_sources[hostname, network].update(address_sources | network_sources)
    for (hostname, network), via in routes.items():
        reason = (
            f"Hostname and route-origin records share {', '.join(sorted(via))}. "
            "The records can describe different times."
        )
        edge = (hostname, "possible_origin_as", network, "inferred", "medium", reason)
        edges[edge].update(route_sources[hostname, network])

    relationships = [Relationship(*key, sources=sorted(edges[key])) for key in sorted(edges)]
    return facts, relationships
