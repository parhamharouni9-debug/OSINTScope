"""Public certificate identities indexed by crt.sh."""

from collections.abc import Sequence
from datetime import datetime
from urllib.parse import urlencode

from ..http import FetchError, HttpClient
from ..models import CollectorResult, Coverage, Observation, utc_now
from ..validation import normalize_domain

_RESULT_LIMIT = 10_000  # crt.sh applies this limit before grouping by certificate.


def _matching_names(raw: str, domain: str) -> list[str]:
    names = set()
    for identity in raw.splitlines():
        wildcard = identity.startswith("*.")
        try:
            hostname = normalize_domain(identity.removeprefix("*."))
        except ValueError:
            continue
        if hostname == domain or hostname.endswith("." + domain):
            names.add(("*." if wildcard else "") + hostname)
    return sorted(names)


def _dates(record: dict) -> dict[str, str]:
    dates = {}
    for field in ("not_before", "not_after", "entry_timestamp"):
        value = record.get(field)
        if isinstance(value, str):
            try:
                datetime.fromisoformat(value)
            except ValueError:
                continue
            dates[field] = value
    return dates


class CertificateCollector:
    key = "ct"
    name = "crt.sh certificate transparency"
    description = "Logged certificate identities, validity dates and explicit subdomain names."
    homepage = "https://crt.sh/"

    def collect(
        self, domain: str, client: HttpClient, prior: Sequence[Observation] = ()
    ) -> CollectorResult:
        domain = normalize_domain(domain)
        query = urlencode({"q": f"%.{domain}", "output": "json", "deduplicate": "Y"})
        try:
            rows = client.get_json(f"https://crt.sh/?{query}")
        except FetchError as exc:
            return CollectorResult(self.key, [], [Coverage(self.key, "failed", str(exc))])
        if not isinstance(rows, list):
            return CollectorResult(
                self.key,
                [],
                [Coverage(self.key, "failed", "Unexpected crt.sh response.")],
            )

        observations = []
        malformed = 0
        matches = 0
        observed_at = utc_now()
        for row in rows[:_RESULT_LIMIT]:
            if not isinstance(row, dict):
                malformed += 1
                continue
            count = row.get("result_count")
            matches += count if type(count) is int and count > 0 else 1
            cert_id = row.get("id")
            raw_names = row.get("name_value")
            if type(cert_id) is not int or cert_id <= 0 or not isinstance(raw_names, str):
                malformed += 1
                continue
            names = _matching_names(raw_names, domain)
            if not names:
                continue
            reference = f"https://crt.sh/?id={cert_id}"
            certificate = f"crt.sh:{cert_id}"
            observations.append(
                Observation(
                    "certificate",
                    domain,
                    certificate,
                    self.key,
                    reference,
                    observed_at,
                    {"names": names, **_dates(row)},
                )
            )
            for name in names:
                if name != domain and not name.startswith("*."):
                    observations.append(
                        Observation(
                            "subdomain",
                            domain,
                            name,
                            self.key,
                            reference,
                            observed_at,
                            {"certificate": certificate},
                        )
                    )

        warnings = []
        if len(rows) >= _RESULT_LIMIT or matches >= _RESULT_LIMIT:
            warnings.append("The search reached the crt.sh identity limit.")
        if malformed:
            warnings.append(f"Skipped {malformed} malformed archive record(s).")
        note = "Certificate names document issuance. Host availability is unverified."
        coverage = Coverage(
            self.key, "partial" if warnings else "complete", " ".join([note, *warnings])
        )
        return CollectorResult(self.key, observations, [coverage])
