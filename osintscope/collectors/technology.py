"""Read the primary page's HTTP Server product from existing public urlscan records."""

import re
from collections.abc import Sequence
from datetime import datetime
from urllib.parse import urlencode
from uuid import UUID

from ..http import FetchError, HttpClient
from ..models import CollectorResult, Coverage, Observation, utc_now
from ..validation import normalize_domain

_SEARCH = "https://urlscan.io/api/v1/search/"
# Keep a single product[/version]. Banner comments may contain personal details.
_SERVER_PRODUCT = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._+~-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9._+~-]{0,31})?)(?=\s|$)"
)


class TechnologyCollector:
    key = "technology"
    name = "urlscan public archive"
    homepage = "https://urlscan.io/docs/search/"
    description = "HTTP Server products recorded by existing public page scans."
    max_scans = 20

    def collect(
        self, domain: str, client: HttpClient, prior: Sequence[Observation] = ()
    ) -> CollectorResult:
        domain = normalize_domain(domain)
        query = urlencode(
            {
                "q": f'task.visibility:public AND page.domain:"{domain}"',
                "size": self.max_scans,
            }
        )
        try:
            payload = client.get_json(f"{_SEARCH}?{query}")
            if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                raise FetchError("Invalid urlscan search response.")
        except (FetchError, ValueError) as exc:
            return CollectorResult(self.key, [], [Coverage(self.key, "failed", str(exc))])

        warnings: set[str] = set()
        rows = payload["results"]
        days = payload.get("search_date_limit_days")
        if isinstance(days, int) and days > 0:
            warnings.add(f"urlscan limited this search to the last {days} days.")
        total = payload.get("total")
        if (
            payload.get("has_more")
            or len(rows) > self.max_scans
            or (isinstance(total, int) and total > len(rows))
        ):
            warnings.add(f"Only the first {self.max_scans} public search results were requested.")
        observations: list[Observation] = []
        observed_at = utc_now()
        for row in rows[: self.max_scans]:
            if not isinstance(row, dict) or not isinstance(row.get("page"), dict):
                warnings.add("A malformed search result was omitted.")
                continue
            page = row["page"]
            task = row.get("task")
            if not isinstance(task, dict) or task.get("visibility") != "public":
                warnings.add("A result without confirmed public visibility was omitted.")
                continue
            try:
                hostname = normalize_domain(page.get("domain") or "")
            except (TypeError, ValueError):
                warnings.add("A result with an invalid final page domain was omitted.")
                continue
            if hostname != domain and not hostname.endswith("." + domain):
                continue
            server = page.get("server")
            if not isinstance(server, str) or not server:
                continue
            product = _SERVER_PRODUCT.match(server.strip())
            if product is None:
                continue
            # Build our own archive citation. Never follow URLs returned by search.
            try:
                scan_id = UUID(str(task.get("uuid") or row.get("_id")))
            except ValueError:
                warnings.add("A result with an invalid archive identifier was omitted.")
                continue
            details = {"field": "HTTP Server"}
            scan_time = task.get("time")
            try:
                if (
                    isinstance(scan_time, str)
                    and len(scan_time) <= 64
                    and datetime.fromisoformat(scan_time).tzinfo is not None
                ):
                    details["scan_time"] = scan_time
            except ValueError:
                pass
            if "scan_time" not in details:
                warnings.add("An archive result has no usable scan timestamp.")
            observations.append(
                Observation(
                    "technology",
                    hostname,
                    product.group(1),
                    self.key,
                    f"https://urlscan.io/result/{scan_id}/",
                    observed_at,
                    details,
                )
            )
        status = "partial" if warnings else "complete"
        return CollectorResult(
            self.key, observations, [Coverage(self.key, status, " ".join(sorted(warnings)))]
        )
