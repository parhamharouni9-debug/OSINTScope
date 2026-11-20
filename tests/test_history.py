"""Exercise durable snapshots, provenance-aware correlation and source-aware diffs."""

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from osintscope.analysis import analyze
from osintscope.comparison import compare
from osintscope.models import Coverage, Investigation, Observation
from osintscope.storage import Repository

DOMAIN = "example.org"
FIRST = "2026-01-01T00:00:00+00:00"
SECOND = "2026-02-01T00:00:00+00:00"


def evidence(
    kind: str,
    value: str,
    source: str = "pdns",
    *,
    subject: str = DOMAIN,
    **details: str,
) -> Observation:
    return Observation(
        kind,
        subject,
        value,
        source,
        f"https://source.example/{source}",
        FIRST,
        details,
    )


def snapshot(
    observations: list[Observation],
    *,
    statuses: dict[str, str] | None = None,
    when: str = FIRST,
) -> Investigation:
    if statuses is None:
        statuses = {"pdns": "complete"}
    deduped, relationships = analyze(DOMAIN, observations)
    return Investigation(
        None,
        DOMAIN,
        when,
        when,
        deduped,
        [Coverage(source, status) for source, status in statuses.items()],
        relationships,
    )


class StorageTests(unittest.TestCase):
    def test_persistent_round_trip_and_history_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "history.db"
            scan = snapshot([evidence("dns", "ns.example.org", rrtype="NS")])
            incomplete = snapshot([], when=SECOND, statuses={"ct": "failed"})
            with Repository(path) as repository:
                second_id = repository.save(incomplete)
                first_id = repository.save(scan)
                third_id = repository.save(incomplete)
                repository.save(replace(scan, domain="separate.example.org"))
            with Repository(path) as repository:
                self.assertEqual(repository.get(first_id), replace(scan, id=first_id))
                self.assertIsNone(repository.get(9999))
                history = repository.history(DOMAIN)
                self.assertEqual([s["id"] for s in history], [third_id, second_id, first_id])
                self.assertEqual(history[0]["status"], "failed")
                self.assertEqual(history[-1]["observations"], 1)
                self.assertEqual(
                    [s.id for s in repository.latest(DOMAIN, 2)], [third_id, second_id]
                )
                self.assertEqual(repository.latest("unknown.example.org"), [])
                self.assertEqual(repository.latest(DOMAIN, 0), [])
                with self.assertRaises(ValueError):
                    repository.latest(DOMAIN, -1)
                with self.assertRaises(ValueError):
                    repository.save(replace(scan, id=first_id))

    def test_failed_save_rolls_back_whole_snapshot(self) -> None:
        with Repository(":memory:") as repository:
            scan = snapshot([evidence("subdomain", "www.example.org")])
            original_id = repository.save(scan)
            invalid = replace(scan, coverage=[Coverage("pdns", "bad-status")])
            with self.assertRaises(sqlite3.IntegrityError):
                repository.save(invalid)
            self.assertEqual([s.id for s in repository.latest(DOMAIN, 10)], [original_id])
            self.assertGreater(repository.save(scan), original_id)

    def test_concurrent_first_use_and_atomic_appends(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"

            def save_one(index: int) -> int:
                with Repository(path) as repository:
                    name = f"item{index}.{DOMAIN}"
                    return repository.save(snapshot([evidence("subdomain", name)]))

            with ThreadPoolExecutor(max_workers=4) as pool:
                scan_ids = list(pool.map(save_one, range(8)))
            self.assertEqual(len(set(scan_ids)), 8)
            with Repository(path) as repository:
                self.assertEqual(len(repository.history(DOMAIN)), 8)

    def test_unrelated_database_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.db"
            connection = sqlite3.connect(path)
            try:
                connection.execute("CREATE TABLE existing (note TEXT)")
                connection.commit()
                with self.assertRaises(sqlite3.DatabaseError):
                    Repository(path)
                names = list(connection.execute("SELECT name FROM sqlite_master"))
                self.assertEqual(names, [("existing",)])
            finally:
                connection.close()


class AnalysisTests(unittest.TestCase):
    def test_dedup_keeps_unique_sources_and_evidence_links(self) -> None:
        first = evidence("dns", "8.8.8.8", rrtype="A")
        later = replace(first, observed_at=SECOND)
        other = replace(first, source="other", reference="https://other.example/dns")
        reference = replace(first, reference="https://source.example/another")
        facts, edges = analyze(DOMAIN, [other, first, reference, later])
        self.assertCountEqual(facts, [other, first, reference])
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].sources, ["other", "pdns"])
        self.assertEqual(edges[0].basis, "observed")

    def test_inference_exposes_intermediate_address_and_both_sources(self) -> None:
        ip = evidence("ip", "8.8.8.8")
        origin = evidence("asn", "AS15169", "asn", subject="8.8.8.8")
        unrelated = replace(origin, value="AS12345", subject="1.1.1.1")
        second_address = replace(ip, value="8.8.4.4")
        second_origin = replace(origin, subject=second_address.value)
        _, edges = analyze(DOMAIN, [origin, unrelated, ip, second_address, second_origin])
        inferred = [edge for edge in edges if edge.basis == "inferred"]
        self.assertEqual(len(inferred), 1)
        edge = inferred[0]
        self.assertEqual((edge.subject, edge.object), (DOMAIN, "AS15169"))
        self.assertIn("8.8.8.8", edge.reason)
        self.assertIn("8.8.4.4", edge.reason)
        self.assertEqual(edge.confidence, "medium")
        self.assertEqual(edge.sources, ["asn", "pdns"])

    def test_nameservers_mail_and_wildcard_certificate(self) -> None:
        cert = replace(
            evidence("certificate", "crt.sh:100", "ct"),
            details={"names": ["*.example.org", "another.example"]},
        )
        _, edges = analyze(
            DOMAIN,
            [
                evidence("dns", "0 .", rrtype="MX"),
                evidence("dns", "10 mail.example.org", rrtype="MX"),
                evidence("dns", "ns.example.org", rrtype="NS"),
                evidence("nameserver", "ns.example.org", "rdap"),
                cert,
            ],
        )
        edges_by_kind = {edge.predicate: edge for edge in edges}
        ns = edges_by_kind["observed_nameserver"]
        self.assertEqual(ns.sources, ["pdns", "rdap"])
        mail = [edge.object for edge in edges if edge.predicate == "observed_mail_exchanger"]
        self.assertEqual(mail, ["mail.example.org"])
        names = [edge.object for edge in edges if edge.predicate == "lists_name"]
        self.assertEqual(names, ["*.example.org"])


class ComparisonTests(unittest.TestCase):
    def test_detects_dns_cert_and_subdomain_observations(self) -> None:
        complete = {"pdns": "complete", "ct": "complete"}
        before = snapshot(
            [
                evidence("dns", "old.example.org", rrtype="NS"),
                evidence("certificate", "crt.sh:1", "ct"),
            ],
            statuses=complete,
        )
        after = snapshot(
            [
                evidence("dns", "new.example.org", rrtype="NS"),
                evidence("certificate", "crt.sh:2", "ct"),
                evidence("subdomain", "www.example.org", "ct"),
            ],
            statuses=complete,
            when=SECOND,
        )
        changes = compare(before, after)
        self.assertEqual({c["kind"] for c in changes["added"]}, {"dns", "certificate", "subdomain"})
        self.assertEqual(
            {c["value"] for c in changes["not_observed"]},
            {"old.example.org", "crt.sh:1"},
        )
        self.assertEqual(changes["removed"], [])
        self.assertEqual(changes["unknown"], [])

    def test_uncertain_when_coverage_fails_is_partial_or_is_omitted(self) -> None:
        host = evidence("subdomain", "www.example.org", "ct")
        before = snapshot([host], statuses={"ct": "complete"})
        for statuses in ({"ct": "failed"}, {"ct": "partial"}, {}):
            with self.subTest(statuses=statuses):
                after = snapshot([], statuses=statuses, when=SECOND)
                for changes in (compare(before, after), compare(after, before)):
                    self.assertEqual(len(changes["unknown"]), 1)
                    self.assertTrue(changes["warnings"])
                    self.assertEqual(changes["added"], [])
                    self.assertEqual(changes["not_observed"], [])
                    self.assertEqual(changes["removed"], [])

    def test_metadata_churn_excluded_but_rrtype_compared(self) -> None:
        before = evidence("dns", "alias.example.org", rrtype="CNAME", ttl="60")
        later = replace(before, details={"rrtype": "CNAME", "ttl": "100"})
        added = replace(before, details={"rrtype": "NS"})
        result = compare(snapshot([before]), snapshot([later, added]))
        self.assertEqual([item["rrtype"] for item in result["added"]], ["NS"])
        self.assertEqual(result["not_observed"], [])
        with self.assertRaises(ValueError):
            compare(snapshot([]), replace(snapshot([]), domain="other.example"))

    def test_asn_changes_require_comparable_ip_lookups(self) -> None:
        complete = {"pdns": "complete", "asn": "complete"}
        ip = evidence("dns", "8.8.8.8", rrtype="A")
        origin = evidence("asn", "AS15169", "asn", subject=ip.value)
        other_ip = evidence("ip", "1.1.1.1")
        other_origin = evidence("asn", "AS13335", "asn", subject=other_ip.value)
        before = snapshot([ip, origin], statuses=complete)
        after = snapshot([other_ip, other_origin], statuses=complete, when=SECOND)
        changes = compare(before, after)
        self.assertEqual({c["subject"] for c in changes["unknown"]}, {ip.value, other_ip.value})
        self.assertEqual([c["kind"] for c in changes["added"]], ["ip"])
        self.assertEqual([c["kind"] for c in changes["not_observed"]], ["dns"])
        self.assertTrue(any("same IP" in warning for warning in changes["warnings"]))

        empty_lookup = snapshot([ip], statuses=complete, when=SECOND)
        absent = compare(before, empty_lookup)
        self.assertEqual([c["value"] for c in absent["not_observed"]], [origin.value])
        self.assertEqual(absent["removed"], [])
        self.assertEqual(absent["unknown"], [])
        self.assertEqual(
            [c["value"] for c in compare(empty_lookup, before)["added"]], [origin.value]
        )

        partial_lookup = snapshot([ip], statuses={**complete, "asn": "partial"})
        self.assertEqual(
            [c["value"] for c in compare(before, partial_lookup)["unknown"]],
            [origin.value],
        )
