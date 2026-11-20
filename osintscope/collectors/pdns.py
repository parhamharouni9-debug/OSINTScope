"""Historical DNS answers from the mnemonic public passive DNS archive."""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from urllib.parse import quote, urlencode

from ..http import FetchError, HttpClient
from ..models import CollectorResult, Coverage, Observation, utc_now
from ..validation import normalize_domain

_RR_TYPES = ("a", "aaaa", "cname", "mx", "ns")
_LIMIT = 1000


def _answer(rrtype: str, raw: str) -> str | None:
    if rrtype in ("A", "AAAA"):
        address = ip_address(raw)
        if address.version != (4 if rrtype == "A" else 6) or "%" in raw:
            raise ValueError("Address family or scope mismatch")
        if not address.is_global or address.is_multicast:
            return None
        return str(address)
    if rrtype == "MX":
        fields = raw.split()
        preference = ""
        if len(fields) == 2:
            number, host = fields
            if not number.isascii() or not number.isdecimal() or int(number) > 65535:
                raise ValueError("Invalid MX preference")
            preference = f"{int(number)} "
        elif len(fields) == 1:
            host = fields[0]
        else:
            raise ValueError("Invalid MX answer")
        if host == ".":
            if preference not in ("", "0 "):
                raise ValueError("Invalid null MX preference")
            return preference + "."
        return preference + normalize_domain(host)
    return normalize_domain(raw)


def _provider_dates(record: dict) -> dict[str, str]:
    dates = {}
    for key, label in (
        ("firstSeenTimestamp", "first_seen"),
        ("lastSeenTimestamp", "last_seen"),
    ):
        millis = record.get(key)
        if type(millis) is int and 0 <= millis < 253402300800000:
            epoch = datetime(1970, 1, 1, tzinfo=UTC)
            dates[label] = (epoch + timedelta(milliseconds=millis)).isoformat()
    return dates


class PassiveDNSCollector:
    key = "pdns"
    name = "mnemonic passive DNS"
    description = "Archived public A, AAAA, CNAME, MX and NS answers for the exact name."
    homepage = (
        "https://docs.mnemonic.no/service-integration-guides/"
        "passivedns/docs/public/01-public_api.html"
    )

    def collect(
        self, domain: str, client: HttpClient, prior: Sequence[Observation] = ()
    ) -> CollectorResult:
        domain = normalize_domain(domain)
        params = urlencode({"rrType": _RR_TYPES, "rrClass": "in", "limit": _LIMIT}, doseq=True)
        url = f"https://api.mnemonic.no/pdns/v3/{quote(domain, safe='')}?{params}"
        try:
            payload = client.get_json(url)
        except FetchError as exc:
            return CollectorResult(self.key, [], [Coverage(self.key, "failed", str(exc))])

        if (
            not isinstance(payload, dict)
            or payload.get("responseCode") != 200
            or not isinstance(payload.get("data"), list)
        ):
            return CollectorResult(
                self.key,
                [],
                [Coverage(self.key, "failed", "Unexpected mnemonic response.")],
            )

        rows = payload["data"]
        observed_at = utc_now()
        observations = []
        malformed = 0
        for row in rows[:_LIMIT]:
            if not isinstance(row, dict):
                malformed += 1
                continue
            if row.get("tlp") != "white" or row.get("rrclass") != "in":
                continue
            owner = row.get("query")
            raw = row.get("answer")
            rrtype = row.get("rrtype")
            if not all(isinstance(field, str) for field in (owner, raw, rrtype)):
                malformed += 1
                continue
            if rrtype.lower() not in _RR_TYPES:
                continue
            try:
                # Simple queries can also match the answer side of unrelated names.
                if normalize_domain(owner) != domain:
                    continue
                rrtype = rrtype.upper()
                value = _answer(rrtype, raw.strip())
            except ValueError:
                malformed += 1
                continue
            if value is None:
                continue
            details = {"rrtype": rrtype, **_provider_dates(row)}
            observations.append(
                Observation("dns", domain, value, self.key, url, observed_at, details)
            )
            if rrtype in ("A", "AAAA"):
                observations.append(
                    Observation("ip", domain, value, self.key, url, observed_at, details)
                )

        warnings = []
        count = payload.get("count")
        if type(count) is not int or count != len(rows) or len(rows) > _LIMIT:
            warnings.append("The archive returned a limited or uncounted result set.")
        if malformed:
            warnings.append(f"Skipped {malformed} malformed archive record(s).")
        note = "Historical DNS sightings can outlive the records they describe."
        coverage = Coverage(
            self.key, "partial" if warnings else "complete", " ".join([note, *warnings])
        )
        return CollectorResult(self.key, observations, [coverage])
