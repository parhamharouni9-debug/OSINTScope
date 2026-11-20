"""Records shared by collection, analysis, persistence and presentation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class Observation:
    kind: str
    subject: str
    value: str
    source: str
    reference: str
    observed_at: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Coverage:
    key: str
    status: str
    message: str = ""


@dataclass(frozen=True)
class CollectorResult:
    source: str
    observations: list[Observation]
    coverage: list[Coverage]


@dataclass(frozen=True)
class Relationship:
    subject: str
    predicate: str
    object: str
    basis: str
    confidence: str
    reason: str
    sources: list[str]


@dataclass(frozen=True)
class Investigation:
    id: int | None
    domain: str
    started_at: str
    finished_at: str
    observations: list[Observation]
    coverage: list[Coverage]
    relationships: list[Relationship]


def coverage_status(coverage: list[Coverage]) -> str:
    statuses = {item.status for item in coverage}
    if statuses == {"complete"}:
        return "complete"
    if not statuses or statuses == {"failed"}:
        return "failed"
    return "partial"
