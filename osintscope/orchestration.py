"""A registry of passive collectors, run in dependency order."""

import logging
from collections.abc import Sequence
from typing import Protocol

from .analysis import analyze
from .collectors.ct import CertificateCollector
from .collectors.pdns import PassiveDNSCollector
from .collectors.registry import AsnCollector, DomainRegistrationCollector
from .collectors.technology import TechnologyCollector
from .http import FetchError, HttpClient
from .models import CollectorResult, Coverage, Investigation, Observation, utc_now
from .validation import normalize_domain

LOG = logging.getLogger(__name__)


class Collector(Protocol):
    key: str
    name: str
    homepage: str
    description: str

    def collect(
        self, domain: str, client: HttpClient, prior: Sequence[Observation] = ()
    ) -> CollectorResult: ...


COLLECTORS: tuple[Collector, ...] = (
    DomainRegistrationCollector(),
    PassiveDNSCollector(),
    AsnCollector(),
    CertificateCollector(),
    TechnologyCollector(),
)


def select_collectors(
    keys: Sequence[str] | None, registry: Sequence[Collector] = COLLECTORS
) -> list[Collector]:
    by_key = {collector.key: collector for collector in registry}
    ordered: dict[str, Collector] = {}
    visiting: set[str] = set()

    def include(key: str) -> None:
        if key in ordered:
            return
        if key not in by_key:
            raise ValueError(f"Unknown source '{key}'. Run osintscope sources for available keys.")
        if key in visiting:
            raise ValueError(f"Circular source dependency at '{key}'.")
        visiting.add(key)
        collector = by_key[key]
        for dependency in getattr(collector, "requires", ()):
            include(dependency)
        ordered[key] = collector
        visiting.remove(key)

    for key in keys or by_key:
        include(key)
    return list(ordered.values())


def investigate(domain: str, client: HttpClient, collectors: Sequence[Collector]) -> Investigation:
    domain = normalize_domain(domain)
    started = utc_now()
    observations: list[Observation] = []
    coverage: list[Coverage] = []
    for collector in collectors:
        failed = {item.key for item in coverage if item.status == "failed"}
        unavailable = failed.intersection(getattr(collector, "requires", ()))
        if unavailable:
            reason = "Required source failed: " + ", ".join(sorted(unavailable)) + "."
            coverage.append(Coverage(collector.key, "failed", reason))
            continue
        LOG.info("Reading %s", collector.name)
        try:
            result = collector.collect(domain, client, tuple(observations))
            if (
                result.source != collector.key
                or len(result.coverage) != 1
                or result.coverage[0].key != collector.key
                or result.coverage[0].status not in {"complete", "partial", "failed"}
                or any(o.source != collector.key for o in result.observations)
            ):
                raise ValueError("Inconsistent collector result")
        except FetchError as exc:
            coverage.append(Coverage(collector.key, "failed", str(exc)))
        except Exception:
            # Isolate extension failures. Verbose logs preserve developer diagnostics.
            LOG.debug("Collector error in %s", collector.key, exc_info=True)
            coverage.append(
                Coverage(collector.key, "failed", "Unexpected collector error. See verbose logs.")
            )
        else:
            observations.extend(result.observations)
            coverage.extend(result.coverage)
    observations, relationships = analyze(domain, observations)
    return Investigation(None, domain, started, utc_now(), observations, coverage, relationships)
