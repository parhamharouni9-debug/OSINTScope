"""Bounded HTTPS reads from public data providers; redirects are disabled."""

import http.client
import json
import logging
import math
import socket
import ssl
from collections.abc import Mapping
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import __version__
from .config import NetworkSettings
from .errors import FetchError
from .rate_limit import RateLedger

LOG = logging.getLogger(__name__)
PROVIDERS = frozenset({"api.mnemonic.no", "crt.sh", "data.iana.org", "stat.ripe.net", "urlscan.io"})
MAX_BYTES = 8 * 1024 * 1024


class _RefuseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise FetchError(f"Provider returned HTTP {code}. Redirects are disabled.")


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        if value.isascii() and value.isdecimal():
            seconds = float(value)
            return seconds if math.isfinite(seconds) else 86400.0
        date = parsedate_to_datetime(value)
        return max(0.0, (date - datetime.now(UTC)).total_seconds())
    except (ValueError, TypeError, OverflowError):
        return None


def _network_reason(reason: object) -> str:
    """Summarize urllib's reason without putting raw URLs or proxy details in reports."""
    if isinstance(reason, TimeoutError):
        return "socket timed out"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "TLS certificate verification failed"
    if isinstance(reason, socket.gaierror):
        return f"DNS lookup failed (errno {reason.errno})"
    if isinstance(reason, http.client.IncompleteRead):
        return "incomplete response body"
    if isinstance(reason, str):
        # URLError can carry free-form text in place of an exception.
        description = reason.lower()
        if "timed out" in description or "timeout" in description:
            return "socket timed out"
        if "connection reset" in description:
            return "connection reset"
        if "tunnel connection failed" in description:
            return "proxy tunnel failed"
        return "unclassified URL error"
    code = getattr(reason, "errno", None)
    name = type(reason).__name__
    return f"{name} (errno {code})" if isinstance(code, int) else name


class HttpClient:
    def __init__(self, domain: str, settings: NetworkSettings, ledger: RateLedger):
        self.domain = domain
        self.settings = settings
        self.ledger = ledger
        self._opener = build_opener(_RefuseRedirect())

    def _record_cooldown(self, host: str, headers: Mapping[str, str], status: int) -> None:
        delay = _retry_after(headers.get("Retry-After"))
        if host == "urlscan.io" and (status == 429 or headers.get("X-Rate-Limit-Remaining") == "0"):
            reset = _retry_after(headers.get("X-Rate-Limit-Reset-After"))
            if reset is not None:
                delay = max(delay or 0, reset)
        if delay is not None or status == 429:
            self.ledger.defer(host, delay if delay is not None else 60.0)

    def get_json(self, url: str, *, allowed_host: str | None = None) -> object:
        """allowed_host is for an HTTPS registry endpoint selected from IANA bootstrap."""
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
            valid = (
                parts.scheme == "https"
                and parts.username is None
                and parts.password is None
                and parts.port in (None, 443)
                and not parts.fragment
                and host
                and not host.endswith(".")
            )
        except ValueError as exc:
            raise FetchError("Invalid provider endpoint.") from exc
        if not valid or (host not in PROVIDERS and host != allowed_host):
            raise FetchError("Endpoint is outside the provider list.")
        if host == self.domain or host.endswith("." + self.domain):
            raise FetchError("The provider endpoint is within the investigated domain.")

        request = Request(
            url,
            headers={
                "Accept": "application/json, application/rdap+json",
                "Accept-Encoding": "identity",
                "User-Agent": f"OSINTScope/{__version__} (passive infrastructure research)",
            },
        )
        attempts = self.settings.retries + 1
        timeout = self.settings.timeout
        for attempt in range(1, attempts + 1):
            self.ledger.acquire(host)
            phase = "opening the request"
            LOG.debug(
                "Request to %s (attempt %d/%d, socket timeout %gs)",
                host,
                attempt,
                attempts,
                timeout,
            )
            try:
                with self._opener.open(request, timeout=timeout) as response:
                    self._record_cooldown(host, response.headers, response.status)
                    if response.status != 200:
                        raise FetchError(f"Unexpected HTTP {response.status} from {host}.")
                    phase = "reading the response"
                    body = response.read(MAX_BYTES + 1)
                    length = response.headers.get("Content-Length")
                    if len(body) > MAX_BYTES:
                        raise FetchError(f"Response from {host} exceeds the 8 MiB limit.")
                    if length and length.isdecimal():
                        expected = int(length)
                        if len(body) < expected:
                            raise http.client.IncompleteRead(body, expected - len(body))
                        if len(body) > expected:
                            raise FetchError(f"Response from {host} exceeds its declared length.")
                    try:
                        return json.loads(body)
                    except (ValueError, UnicodeError, RecursionError) as exc:
                        raise FetchError(f"Invalid JSON from {host}.") from exc
            except HTTPError as exc:
                code = exc.code
                self._record_cooldown(host, exc.headers or {}, code)
                exc.close()
                message = f"Provider {host} returned HTTP {code}."
                if code not in (408, 429, 500, 502, 503, 504) or attempt == attempts:
                    raise FetchError(message) from exc
            except (URLError, OSError, http.client.HTTPException) as exc:
                reason = exc.reason if isinstance(exc, URLError) else exc
                message = (
                    f"Unable to read {host} while {phase}: {_network_reason(reason)} "
                    f"(attempt {attempt}/{attempts}, socket timeout {timeout:g}s)."
                )
                LOG.debug("%s", message)
                if attempt == attempts or isinstance(reason, ssl.SSLCertVerificationError):
                    raise FetchError(message) from exc
            self.ledger.defer(host, 2 ** (attempt - 1))
        raise AssertionError("unreachable")
