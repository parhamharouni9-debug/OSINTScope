"""Domain registration and BGP origin data from public registries."""

import ipaddress
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from urllib.parse import urlencode, urlsplit

from ..http import FetchError, HttpClient
from ..models import CollectorResult, Coverage, Observation, utc_now
from ..validation import normalize_domain

_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
_NETWORK_INFO = "https://stat.ripe.net/data/network-info/data.json"
_EVENTS = ("registration", "expiration", "last changed")


def _registry_url(bootstrap: object, domain: str) -> tuple[str, str]:
    """Select the longest IANA label match (RFC 9224), then an HTTPS service."""
    if not isinstance(bootstrap, dict) or not isinstance(bootstrap.get("services"), list):
        raise FetchError("Invalid IANA bootstrap response.")
    candidates: list[str] = []
    best = 0
    for service in bootstrap["services"]:
        if not isinstance(service, list) or len(service) != 2:
            continue
        suffixes, bases = service
        if not isinstance(suffixes, list) or not isinstance(bases, list):
            continue
        for suffix in suffixes:
            if not isinstance(suffix, str) or not suffix:
                continue
            suffix = suffix.lower()
            if domain != suffix and not domain.endswith("." + suffix):
                continue
            if len(suffix) > best:
                best = len(suffix)
                candidates.clear()
            if len(suffix) == best:
                candidates.extend(base for base in bases if isinstance(base, str))

    for base in candidates:
        try:
            parsed = urlsplit(base)
            host = normalize_domain(parsed.hostname or "")
            if (
                parsed.scheme != "https"
                or parsed.netloc.lower() != host
                or parsed.query
                or parsed.fragment
                or "\\" in base
            ):
                continue
            if host == domain or host.endswith("." + domain):
                continue
            path = parsed.path.rstrip("/")
            return f"https://{host}{path}/domain/{domain}", host
        except ValueError:
            continue
    raise ValueError("IANA lists no eligible HTTPS registry for this name.")


def _event_date(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        moment = datetime.fromisoformat(value)
        if moment.tzinfo is not None:
            return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        pass
    return None


class DomainRegistrationCollector:
    key = "rdap"
    name = "Domain registration (RDAP)"
    homepage = "https://www.iana.org/assignments/rdap-dns"
    description = "IANA bootstrap and the registry's public technical domain record."

    def collect(
        self, domain: str, client: HttpClient, prior: Sequence[Observation] = ()
    ) -> CollectorResult:
        try:
            domain = normalize_domain(domain)
            url, host = _registry_url(client.get_json(_BOOTSTRAP), domain)
            # Only the selected IANA host is authorized for this single request.
            record = client.get_json(url, allowed_host=host)
            if not isinstance(record, dict) or record.get("objectClassName") != "domain":
                raise ValueError("Registry did not return an RDAP domain record.")
            label = record.get("ldhName") or record.get("unicodeName")
            if not isinstance(label, str) or normalize_domain(label) != domain:
                raise ValueError("Registry returned a record for a different name.")
        except (FetchError, ValueError) as exc:
            return CollectorResult(self.key, [], [Coverage(self.key, "failed", str(exc))])

        observations: list[Observation] = []
        warnings: set[str] = set()
        now = utc_now()

        def entries(field: str) -> list:
            values = record.get(field, [])
            if isinstance(values, list):
                return values
            warnings.add("Registry returned a malformed field.")
            return []

        def add_fact(field: str, value: str) -> None:
            observations.append(
                Observation(
                    "registration",
                    domain,
                    f"{field}: {value}",
                    self.key,
                    url,
                    now,
                    {"field": field},
                )
            )

        for status in entries("status"):
            if isinstance(status, str) and re.fullmatch(r"[a-z][a-z -]{0,50}", status):
                add_fact("status", status)
            else:
                warnings.add("An unsupported registry status was omitted.")
        for event in entries("events"):
            if not isinstance(event, dict):
                warnings.add("Registry returned a malformed event.")
                continue
            action = event.get("eventAction")
            if action in _EVENTS:
                date = _event_date(event.get("eventDate"))
                if date:
                    add_fact(action, date)
                else:
                    warnings.add("A registry event date could not be parsed.")
        for entity in entries("entities"):
            if not isinstance(entity, dict) or not isinstance(entity.get("roles"), list):
                continue
            if "registrar" not in entity["roles"]:
                continue
            ids = entity.get("publicIds", [])
            if isinstance(ids, list):
                for item in ids:
                    if isinstance(item, dict) and item.get("type") == "IANA Registrar ID":
                        identifier = str(item.get("identifier", ""))
                        if re.fullmatch(r"[0-9]{1,10}", identifier):
                            add_fact("registrar ID", identifier)
        for ns in entries("nameservers"):
            value = None
            if isinstance(ns, dict):
                value = ns.get("ldhName") or ns.get("unicodeName")
            try:
                name = normalize_domain(value if isinstance(value, str) else "")
            except ValueError:
                warnings.add("A registry nameserver could not be parsed.")
                continue
            observations.append(Observation("nameserver", domain, name, self.key, url, now))
        notices = entries("notices") + entries("remarks")
        if record.get("redacted") or any(
            isinstance(note, dict) and "truncated" in str(note.get("type", "")).lower()
            for note in notices
        ):
            warnings.add("The registry identified redacted or truncated data.")
        if not observations:
            warnings.add("The record contains no supported technical fields.")
        status = "partial" if warnings else "complete"
        return CollectorResult(
            self.key, observations, [Coverage(self.key, status, " ".join(sorted(warnings)))]
        )


def _origins(payload: object, ip: str) -> tuple[list[str], str]:
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise ValueError("RIPEstat did not return a successful response.")
    data = payload.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("asns"), list):
        raise FetchError("Invalid RIPEstat network-info record.")
    if not data["asns"]:
        return [], ""
    try:
        prefix = ipaddress.ip_network(data.get("prefix"))
    except (ValueError, TypeError):
        raise ValueError("RIPEstat returned an invalid routing prefix.") from None
    if ipaddress.ip_address(ip) not in prefix:
        raise ValueError("RIPEstat returned a prefix for a different address.")
    asns: set[int] = set()
    for value in data["asns"]:
        number = str(value)
        if not re.fullmatch(r"[0-9]{1,10}", number) or not 0 < int(number) < 2**32:
            raise ValueError("RIPEstat returned an invalid ASN.")
        asns.add(int(number))
    return [f"AS{asn}" for asn in sorted(asns)], str(prefix)


class AsnCollector:
    key = "asn"
    name = "RIPEstat routing origins"
    homepage = "https://stat.ripe.net/docs/data-api/api-endpoints/network-info.html"
    description = "Announcing ASNs and covering BGP prefixes for archived public addresses."
    requires = ("pdns",)
    max_ips = 5

    def collect(
        self, domain: str, client: HttpClient, prior: Sequence[Observation] = ()
    ) -> CollectorResult:
        ips = [
            item.value
            for item in prior
            if (item.subject == domain or item.subject.endswith("." + domain))
            and (
                item.kind == "ip"
                or (item.kind == "dns" and item.details.get("rrtype") in ("A", "AAAA"))
            )
        ]
        return self.collect_ips(domain, ips, client)

    def collect_ips(self, domain: str, ips: list[str], client: HttpClient) -> CollectorResult:
        addresses: set[str] = set()
        for value in ips:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_global and not address.is_multicast and "%" not in value:
                addresses.add(str(address))
        if not addresses:
            return CollectorResult(
                self.key,
                [],
                [
                    Coverage(
                        self.key, "partial", "No public IP observations were available to enrich."
                    )
                ],
            )

        observations: list[Observation] = []
        warnings: set[str] = set()
        if len(addresses) > self.max_ips:
            warnings.add(
                f"RIPEstat lookup limited to {self.max_ips} of {len(addresses)} addresses."
            )
        successes = 0
        for ip in sorted(addresses)[: self.max_ips]:
            url = _NETWORK_INFO + "?" + urlencode({"resource": ip, "sourceapp": "OSINTScope"})
            try:
                asns, prefix = _origins(client.get_json(url), ip)
            except (FetchError, ValueError) as exc:
                warnings.add(f"{ip}: {exc}")
                continue
            successes += 1
            observed_at = utc_now()
            for asn in asns:
                observations.append(
                    Observation("asn", ip, asn, self.key, url, observed_at, {"prefix": prefix})
                )
        if not successes:
            status = "failed"
        elif warnings:
            status = "partial"
        else:
            status = "complete"
        return CollectorResult(
            self.key, observations, [Coverage(self.key, status, " ".join(sorted(warnings)))]
        )
