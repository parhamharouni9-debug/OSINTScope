import io
import socket
import sqlite3
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch
from urllib.error import HTTPError, URLError

from osintscope.config import NetworkSettings
from osintscope.http import FetchError, HttpClient, _RefuseRedirect, _retry_after
from osintscope.rate_limit import RateLedger


def response(data=b'{"ok":true}', length=None):
    stream = io.BytesIO(data)
    stream.status = 200
    stream.headers = {"Content-Length": str(len(data) if length is None else length)}
    return stream


class TransportTests(unittest.TestCase):
    url = "https://crt.sh/?q=example.com"

    def setUp(self):
        self.ledger = Mock(spec=RateLedger)
        self.client = HttpClient("example.com", NetworkSettings(3, 1), self.ledger)
        self.opener = Mock()
        self.client._opener = self.opener

    def test_retries_transient_errors_with_budget(self):
        self.opener.open.side_effect = [URLError("timeout"), response()]
        self.assertEqual(self.client.get_json(self.url), {"ok": True})
        self.assertEqual(self.ledger.acquire.call_count, 2)
        self.ledger.defer.assert_called_once_with("crt.sh", 1)
        self.assertEqual(self.opener.open.call_args.kwargs["timeout"], 3)

    def test_wrapped_timeout_and_reset_recover_with_configured_timeout(self):
        self.client.settings = NetworkSettings(timeout=17.5, retries=2)
        self.opener.open.side_effect = [
            URLError(TimeoutError("private fixture detail")),
            URLError(ConnectionResetError("private fixture detail")),
            response(),
        ]
        with self.assertLogs("osintscope.http", level="DEBUG") as logs:
            self.assertEqual(self.client.get_json(self.url), {"ok": True})

        self.assertEqual([c.kwargs["timeout"] for c in self.opener.open.call_args_list], [17.5] * 3)
        self.assertEqual(self.ledger.acquire.call_args_list, [call("crt.sh")] * 3)
        self.assertEqual(self.ledger.defer.call_args_list, [call("crt.sh", 1), call("crt.sh", 2)])
        diagnostics = "\n".join(logs.output).lower()
        self.assertRegex(diagnostics, r"timed out|timeouterror")
        self.assertIn("reset", diagnostics)
        self.assertIn("17.5", diagnostics)
        self.assertNotIn("private fixture detail", diagnostics)

    def test_exhausted_dns_error_retains_final_exception(self):
        first = URLError(TimeoutError())
        last = URLError(socket.gaierror(socket.EAI_AGAIN, "private resolver detail"))
        self.opener.open.side_effect = [first, last]
        with self.assertRaises(FetchError) as caught:
            self.client.get_json(self.url)

        self.assertIs(caught.exception.__cause__, last)
        summary = str(caught.exception).lower()
        self.assertIn("dns", summary)
        self.assertIn("opening", summary)
        self.assertRegex(summary, r"2 attempts|attempt 2[/ ]")
        self.assertNotIn("private resolver detail", summary)
        self.assertEqual(self.opener.open.call_count, 2)
        self.ledger.defer.assert_called_once_with("crt.sh", 1)

    def test_certificate_verification_failure_stops_without_retry(self):
        failed = URLError(ssl.SSLCertVerificationError(1, "private verification detail"))
        self.opener.open.side_effect = failed
        with self.assertRaises(FetchError) as caught:
            self.client.get_json(self.url)

        self.assertIs(caught.exception.__cause__, failed)
        self.assertIn("certificate", str(caught.exception).lower())
        self.assertNotIn("private verification detail", str(caught.exception))
        self.opener.open.assert_called_once()
        self.ledger.defer.assert_not_called()

    def test_http_policy_errors_and_retry_after(self):
        for status in (401, 402, 403, 404):
            self.opener.reset_mock()
            self.opener.open.side_effect = HTTPError(self.url, status, "", {}, io.BytesIO())
            with self.subTest(status=status), self.assertRaisesRegex(FetchError, str(status)):
                self.client.get_json(self.url)
            self.opener.open.assert_called_once()
        limited = HTTPError(self.url, 429, "", {"Retry-After": "7"}, io.BytesIO())
        self.opener.open.side_effect = [limited, response()]
        self.assertEqual(self.client.get_json(self.url), {"ok": True})
        self.ledger.defer.assert_any_call("crt.sh", 7)
        self.assertEqual(_retry_after("Fri, 31 Dec 1999 23:59:59 GMT"), 0)
        self.assertIsNone(_retry_after("malformed"))

    def test_request_boundary(self):
        for url in [
            "http://crt.sh/",
            "https://user@crt.sh/",
            "https://crt.sh:80/",
            "https://foreign.test/",
            "file:///secret",
            "https://crt.sh/#frag",
            "https://example.com/",
            "https://registry.example.com/",
        ]:
            with self.subTest(url=url), self.assertRaises(FetchError):
                self.client.get_json(url, allowed_host="registry.example.com")
        with self.assertRaises(FetchError):
            _RefuseRedirect().redirect_request(
                None, io.BytesIO(), 302, "", {}, "https://example.com/"
            )
        self.opener.open.assert_not_called()
        self.ledger.acquire.assert_not_called()

    def test_successful_final_urlscan_request_records_quota_reset(self):
        stream = response()
        stream.headers.update({"X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset-After": "537"})
        self.opener.open.return_value = stream
        self.assertEqual(self.client.get_json("https://urlscan.io/api/v1/search/"), {"ok": True})
        self.ledger.defer.assert_called_once_with("urlscan.io", 537)

    def test_response_validation(self):
        with patch("osintscope.http.MAX_BYTES", 16):
            for stream in [response(b"x"), response(b"x" * 17)]:
                self.opener.open.return_value = stream
                with self.assertRaises(FetchError):
                    self.client.get_json(self.url)
                self.assertTrue(stream.closed)

    def test_content_length_mismatch_retries_with_fresh_response(self):
        short = response(b"{}", length=11)
        self.opener.open.side_effect = [short, response()]
        self.assertEqual(self.client.get_json(self.url), {"ok": True})
        self.assertTrue(short.closed)
        self.assertEqual(self.opener.open.call_count, 2)
        self.ledger.defer.assert_called_once_with("crt.sh", 1)

    def test_repeated_short_responses_exhaust_budget(self):
        streams = [response(b"{}", length=11), response(b"{}", length=11)]
        self.opener.open.side_effect = streams
        with self.assertRaisesRegex(FetchError, r"(?i)incomplete|truncated|short") as caught:
            self.client.get_json(self.url)
        self.assertIn("reading", str(caught.exception).lower())
        self.assertTrue(all(stream.closed for stream in streams))
        self.assertEqual(self.opener.open.call_count, 2)
        self.ledger.defer.assert_called_once_with("crt.sh", 1)


class RateLimitTests(unittest.TestCase):
    def test_daily_cap_and_expiry_survive_reopen(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "requests.sqlite3"
            ledger = RateLedger(path)
            ledger.close()
            with sqlite3.connect(path) as db:
                db.executemany("INSERT INTO mnemonic_requests VALUES (?)", [(90000,)] * 1000)
            db.close()
            ledger = RateLedger(path)
            try:
                with patch("osintscope.rate_limit.time.time", return_value=100000):
                    with self.assertRaisesRegex(FetchError, "quota"):
                        ledger.acquire("api.mnemonic.no")
                    ledger.defer("crt.sh", 90)
                with patch("osintscope.rate_limit.time.time", return_value=100001):
                    with self.assertRaisesRegex(FetchError, "cooldown"):
                        ledger.acquire("crt.sh")
                with patch("osintscope.rate_limit.time.time", return_value=200000):
                    ledger.acquire("api.mnemonic.no")
            finally:
                ledger.close()
