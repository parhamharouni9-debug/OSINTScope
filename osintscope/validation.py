"""Canonical DNS names at the CLI and source ingestion boundaries."""

import idna


def normalize_domain(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter a fully qualified domain name (for example example.com).")
    value = value.strip()
    try:
        name = idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise ValueError(
            "Invalid DNS name. Supply a domain without a URL, port, or wildcard."
        ) from exc
    name = name.removesuffix(".")
    if "." not in name or name.rsplit(".", 1)[1].isdigit():
        raise ValueError("Expected a fully qualified domain with a nonnumeric final label.")
    return name
