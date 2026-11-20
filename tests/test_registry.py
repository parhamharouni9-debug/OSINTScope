import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from osintscope.collectors.registry import AsnCollector, DomainRegistrationCollector
from osintscope.collectors.technology import TechnologyCollector
from osintscope.http import FetchError, HttpClient
from osintscope.models import Observation


def fake_client(*responses: object) -> Mock:
    client = Mock(spec=HttpClient)
    client.get_json.side_effect = responses
    return client


def bootstrap(*bases: str) -> dict:
    return {"services": [[["com"], list(bases)]]}


class RegistrationTests(unittest.TestCase):
    def test_registry_selection_and_contact_minimization(self) -> None:
        index = bootstrap("https://broad.registry.net")
        index["services"].append([["example.com"], ["https://rdap.registry.net/v1"]])
        source = {
            "objectClassName": "domain",
            "ldhName": "EXAMPLE.COM",
            "nameservers": [{"ldhName": "NS.REGISTRY.NET."}],
            "events": [
                {"eventAction": "registration", "eventDate": "2001-01-01T04:00:00+04:00"},
                {"eventAction": "last update of RDAP database", "eventDate": "volatile"},
            ],
            "status": ["active"],
            "entities": [
                {"roles": ["registrant"], "vcardArray": ["private@example.com"]},
                {
                    "roles": ["registrar"],
                    "publicIds": [{"type": "IANA Registrar ID", "identifier": "123"}],
                },
            ],
            "links": [{"href": "https://ignored.example.com"}],
        }
        client = fake_client(index, source)
        result = DomainRegistrationCollector().collect("example.com", client)
        url = "https://rdap.registry.net/v1/domain/example.com"
        self.assertEqual(client.get_json.call_count, 2)
        client.get_json.assert_called_with(url, allowed_host="rdap.registry.net")
        self.assertEqual(result.coverage[0].status, "complete")
        self.assertEqual(
            {item.value for item in result.observations},
            {
                "registration: 2001-01-01T00:00:00Z",
                "status: active",
                "registrar ID: 123",
                "ns.registry.net",
            },
        )
        self.assertTrue(all(item.reference == url for item in result.observations))
        self.assertNotIn("private@example.com", repr(result))

    def test_invalid_endpoints_and_exact_label_boundary(self) -> None:
        index = bootstrap(
            "http://rdap.registry.net",
            "https://ns.example.com",
            "https://127.0.0.1",
            "https://corp@rdap.registry.net",
            "https://rdap.registry.net:443",
            "https://rdap.registry.net?p=1",
        )
        index["services"].append([["ample.com"], ["https://other.registry.net"]])
        client = fake_client(index)
        result = DomainRegistrationCollector().collect("example.com", client)
        self.assertEqual(client.get_json.call_count, 1)
        self.assertEqual(result.coverage[0].status, "failed")

    def test_wrong_domain_and_provider_failure(self) -> None:
        for response in (
            {"objectClassName": "domain", "ldhName": "wrong.example"},
            FetchError("HTTP 429"),
        ):
            with self.subTest(response=response):
                client = fake_client(bootstrap("https://rdap.registry.net"), response)
                result = DomainRegistrationCollector().collect("example.com", client)
                self.assertEqual(result.coverage[0].status, "failed")
                self.assertEqual(result.observations, [])

    def test_redaction_and_malformed_fields_preserve_valid_observations(self) -> None:
        source = {
            "objectClassName": "domain",
            "ldhName": "example.com",
            "nameservers": None,
            "events": [{"eventAction": "expiration", "eventDate": "tomorrow"}],
            "status": ["active"],
            "remarks": [{"type": "object truncated due to authorization"}],
        }
        client = fake_client(bootstrap("https://rdap.registry.net"), source)
        result = DomainRegistrationCollector().collect("example.com", client)
        self.assertEqual(result.coverage[0].status, "partial")
        self.assertEqual([obs.value for obs in result.observations], ["status: active"])


class RoutingTests(unittest.TestCase):
    def test_multiple_origins_single_ip_request_and_input_filtering(self) -> None:
        def obs(kind: str, host: str, value: str) -> Observation:
            return Observation(kind, host, value, "pdns", "archive", "now", {"rrtype": "A"})

        prior = [
            obs("dns", "example.com", "1.1.1.1"),
            obs("ip", "example.com", "1.1.1.1"),
            obs("ip", "example.com", "127.0.0.1"),
            obs("ip", "example.com", "224.0.0.10"),
            obs("ip", "other.example", "8.8.8.8"),
        ]
        client = fake_client(
            {
                "status": "ok",
                "data": {
                    "asns": [13335, "123", "13335"],
                    "prefix": "1.1.1.0/24",
                },
            }
        )
        result = AsnCollector().collect("example.com", client, prior)
        self.assertEqual(result.coverage[0].status, "complete")
        self.assertEqual([obs.value for obs in result.observations], ["AS123", "AS13335"])
        self.assertTrue(all(obs.details["prefix"] == "1.1.1.0/24" for obs in result.observations))
        client.get_json.assert_called_once()

    def test_bounded_calls_and_one_failed_ip(self) -> None:
        client = fake_client(
            {"status": "ok", "data": {"asns": [], "prefix": None}}, FetchError("HTTP 503")
        )
        collector = AsnCollector()
        collector.max_ips = 2
        result = collector.collect_ips("example.com", ["1.1.1.1", "8.8.4.4", "8.8.8.8"], client)
        self.assertEqual(result.coverage[0].status, "partial")
        self.assertIn("2 of 3", result.coverage[0].message)
        self.assertIn("503", result.coverage[0].message)
        self.assertEqual(client.get_json.call_count, 2)

    def test_invalid_origin_data_or_missing_inputs(self) -> None:
        for prefix, asn in [("1.0.0.0/24", "1"), ("1.1.1.0/24", "AS64496")]:
            with self.subTest(prefix=prefix):
                client = fake_client({"status": "ok", "data": {"asns": [asn], "prefix": prefix}})
                result = AsnCollector().collect_ips("example.com", ["1.1.1.1"], client)
                self.assertEqual(result.coverage[0].status, "failed")
        client = fake_client()
        result = AsnCollector().collect("example.com", client)
        self.assertEqual(result.coverage[0].status, "partial")
        client.get_json.assert_not_called()


class TechnologyTests(unittest.TestCase):
    def test_search_only_public_in_scope_final_pages(self) -> None:
        uid = "01234567-89ab-cdef-0123-456789abcdef"
        task = {"visibility": "public", "uuid": uid, "time": "2026-01-02T14:00:00Z"}
        page = {"server": "Apache/2.4 (admin@example.com)", "domain": "www.example.com"}
        client = fake_client(
            {
                "results": [
                    {"page": page, "task": task, "result": "https://ignored.example"},
                    {"page": {**page, "domain": "notexample.com"}, "task": task},
                    {"page": page, "task": {**task, "visibility": "unlisted"}},
                ],
                "total": 200,
                "search_date_limit_days": 30,
            }
        )
        result = TechnologyCollector().collect("example.com", client)
        self.assertEqual(result.coverage[0].status, "partial")
        self.assertIn("30 days", result.coverage[0].message)
        self.assertEqual(len(result.observations), 1)
        obs = result.observations[0]
        self.assertEqual((obs.subject, obs.value), ("www.example.com", "Apache/2.4"))
        self.assertEqual(obs.reference, f"https://urlscan.io/result/{uid}/")
        self.assertEqual(obs.details["scan_time"], task["time"])
        self.assertNotIn("admin@example.com", repr(result))
        client.get_json.assert_called_once()
        url = urlsplit(client.get_json.call_args.args[0])
        self.assertEqual((url.netloc, url.path), ("urlscan.io", "/api/v1/search/"))
        self.assertIn("task.visibility:public", parse_qs(url.query)["q"][0])

    def test_empty_invalid_and_unavailable_searches(self) -> None:
        for payload, status in [
            ({"results": []}, "complete"),
            ({"error": True}, "failed"),
            (FetchError("HTTP 429"), "failed"),
        ]:
            with self.subTest(payload=payload):
                result = TechnologyCollector().collect("example.com", fake_client(payload))
                self.assertEqual(result.coverage[0].status, status)
                self.assertEqual(result.observations, [])
