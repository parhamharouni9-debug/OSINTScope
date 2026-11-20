import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit

from osintscope.collectors.ct import CertificateCollector
from osintscope.collectors.pdns import PassiveDNSCollector
from osintscope.config import NetworkSettings
from osintscope.http import FetchError, HttpClient


def archived(rrtype: str, answer: str, owner: str = "Example.COM.") -> dict:
    return {
        "rrtype": rrtype,
        "query": owner,
        "answer": answer,
        "rrclass": "in",
        "tlp": "white",
        "firstSeenTimestamp": 1_000,
    }


def page(*records: dict, count: int | None = None) -> dict:
    return {
        "responseCode": 200,
        "count": len(records) if count is None else count,
        "data": list(records),
    }


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock(spec=HttpClient)

    def test_only_scoped_public_dns_including_null_mx(self):
        self.client.get_json.return_value = page(
            archived("a", "8.8.8.8"),
            archived("aaaa", "2606:4700:4700:0000::1111"),
            archived("ns", "NS1.EXAMPLE.NET."),
            archived("mx", "0010 MX.Example.NET."),
            archived("mx", "0 ."),
            archived("cname", "Target.example.org."),
            archived("a", "127.0.0.1"),
            archived("a", "224.0.0.1"),
            archived("mx", "example.com.", owner="another.com."),
            {**archived("a", "1.1.1.1"), "tlp": "red"},
            {**archived("a", "1.1.1.1"), "rrclass": "chaos"},
        )
        result = PassiveDNSCollector().collect("Example.com.", self.client)
        self.assertEqual(result.coverage[0].status, "complete")
        dns = {o.value for o in result.observations if o.kind == "dns"}
        self.assertEqual(
            dns,
            {
                "8.8.8.8",
                "2606:4700:4700::1111",
                "ns1.example.net",
                "10 mx.example.net",
                "0 .",
                "target.example.org",
            },
        )
        ips = {o.value for o in result.observations if o.kind == "ip"}
        self.assertEqual(ips, {"8.8.8.8", "2606:4700:4700::1111"})
        for obs in result.observations:
            self.assertEqual(obs.subject, "example.com")
            self.assertEqual(obs.details["first_seen"], "1970-01-01T00:00:01+00:00")
            self.assertEqual(obs.reference, self.client.get_json.call_args.args[0])
        parts = urlsplit(self.client.get_json.call_args.args[0])
        self.assertEqual(parts.hostname, "api.mnemonic.no")
        self.assertEqual(parts.path, "/pdns/v3/example.com")

    def test_partial_dns_preserves_good_rows(self):
        self.client.get_json.return_value = page(
            archived("MX", "mx.example.net."),
            archived("a", "not an IP"),
            archived("aaaa", "1.1.1.1"),
            archived("mx", "90000 mx.example.net"),
            count=1005,
        )
        result = PassiveDNSCollector().collect("example.com", self.client)
        self.assertEqual(result.coverage[0].status, "partial")
        self.assertIn("3 malformed", result.coverage[0].message)
        self.assertIn("limited", result.coverage[0].message)
        self.assertEqual([o.value for o in result.observations], ["mx.example.net"])

    def test_certificate_names_are_scoped_and_wildcards_remain_patterns(self):
        self.client.get_json.return_value = [
            {
                "id": 123,
                "name_value": (
                    "Example.com\nAPI.example.com.\napi.example.com\n*.www.example.com"
                    "\nevil-example.com\nexample.com.other.net\ntest@example.com"
                ),
                "not_before": "2025-04-03T17:00:00",
                "not_after": "unparseable",
                "common_name": "private@example.com",
                "result_count": 2,
            }
        ]
        result = CertificateCollector().collect("example.com", self.client)
        self.assertEqual(result.coverage[0].status, "complete")
        cert, name = result.observations
        self.assertEqual(cert.value, "crt.sh:123")
        self.assertEqual(cert.reference, "https://crt.sh/?id=123")
        self.assertEqual(
            cert.details,
            {
                "names": ["*.www.example.com", "api.example.com", "example.com"],
                "not_before": "2025-04-03T17:00:00",
            },
        )
        self.assertEqual((name.kind, name.value), ("subdomain", "api.example.com"))
        self.assertEqual(name.reference, cert.reference)
        parts = urlsplit(self.client.get_json.call_args.args[0])
        self.assertEqual(parts.hostname, "crt.sh")
        self.assertEqual(parse_qs(parts.query)["q"], ["%.example.com"])

    def test_ct_reports_provider_cap_and_malformed_rows(self):
        self.client.get_json.return_value = [
            {"id": True, "name_value": "www.example.com"},
            {"id": 1, "name_value": "*.example.com", "result_count": 10_000},
        ]
        result = CertificateCollector().collect("example.com", self.client)
        self.assertEqual(result.coverage[0].status, "partial")
        self.assertIn("limit", result.coverage[0].message)
        self.assertIn("1 malformed", result.coverage[0].message)
        self.assertEqual([o.kind for o in result.observations], ["certificate"])

    def test_ct_exhausted_wrapped_timeout_returns_failed_coverage(self):
        client = HttpClient("cloudflare.com", NetworkSettings(), Mock())
        failure = URLError(TimeoutError("sensitive proxy detail"))
        with patch.object(client._opener, "open", side_effect=failure) as opened:
            result = CertificateCollector().collect("cloudflare.com", client)

        self.assertEqual(opened.call_count, 2)
        for args, kwargs in opened.call_args_list:
            self.assertEqual(
                args[0].full_url, "https://crt.sh/?q=%25.cloudflare.com&output=json&deduplicate=Y"
            )
            self.assertEqual(kwargs["timeout"], 10)
        self.assertEqual(result.observations, [])
        self.assertEqual(result.coverage[0].status, "failed")
        self.assertIn("socket timed out", result.coverage[0].message)
        self.assertIn("attempt 2/2", result.coverage[0].message)
        self.assertNotIn("sensitive proxy detail", result.coverage[0].message)

    def test_failed_response_is_distinct_from_no_matches(self):
        for collector, empty, invalid in [
            (CertificateCollector(), [], {"error": "temporary"}),
            (PassiveDNSCollector(), page(), {"responseCode": 402, "data": []}),
        ]:
            with self.subTest(source=collector.key):
                self.client.get_json.return_value = invalid
                result = collector.collect("example.com", self.client)
                self.assertEqual(result.coverage[0].status, "failed")
                self.client.get_json.return_value = empty
                result = collector.collect("example.com", self.client)
                self.assertEqual(result.coverage[0].status, "complete")
                self.assertEqual(result.observations, [])

    def test_fetch_failure_is_recorded_for_either_archive(self):
        self.client.get_json.side_effect = FetchError("Source timeout")
        for collector in (CertificateCollector(), PassiveDNSCollector()):
            with self.subTest(source=collector.key):
                result = collector.collect("example.com", self.client)
                self.assertEqual(result.coverage[0].status, "failed")
                self.assertIn("timeout", result.coverage[0].message)
                self.assertEqual(result.observations, [])
