import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from osintscope.cli import main
from osintscope.http import FetchError
from osintscope.models import CollectorResult, Coverage, Investigation, Observation
from osintscope.orchestration import investigate, select_collectors
from osintscope.reporting import html_report


class CommandTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.db = self.root / "history.db"
        data = patch("osintscope.cli.data_directory", return_value=self.root)
        data.start()
        self.addCleanup(data.stop)

    def invoke(self, *args, global_db=False):
        out, err = io.StringIO(), io.StringIO()
        db_arg = ["--db", str(self.db)]
        argv = db_arg + list(args) if global_db else list(args) + db_arg
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_full_history_and_reports(self):
        snapshot = [{"id": 15, "name_value": "old.example.com"}]
        with patch("osintscope.http.HttpClient.get_json", return_value=snapshot) as fetch:
            self.assertEqual(self.invoke("scan", "Example.COM.", "--source", "ct")[0], 0)
            snapshot[:] = [{"id": 16, "name_value": "new.example.com"}]
            self.assertEqual(
                self.invoke("scan", "example.com", "--source", "ct", global_db=True)[0], 0
            )
            self.assertEqual(fetch.call_count, 2)
        status, listing, _ = self.invoke("history", "example.com")
        self.assertEqual(status, 0)
        self.assertEqual([line.split()[0] for line in listing.splitlines()[1:]], ["2", "1"])
        diff = json.loads(self.invoke("diff", "example.com", "--format", "json")[1])
        self.assertEqual({c["value"] for c in diff["added"]}, {"new.example.com", "crt.sh:16"})
        self.assertEqual(diff["removed"], [])
        report = json.loads(self.invoke("report", "example.com", "--format", "json")[1])
        self.assertEqual(report["comparison"], diff)
        self.assertEqual(report["summary"]["observation_count"], 2)
        self.assertTrue(
            all(
                o["reference"] and o["observed_at"] for o in report["investigation"]["observations"]
            )
        )
        file = self.root / "reports" / "early.html"
        status, _, _ = self.invoke("report", "example.com", "--scan-id", "1", "-o", str(file))
        self.assertEqual(status, 0)
        content = file.read_text(encoding="utf-8")
        self.assertIn("First stored investigation", content)
        self.assertIn("old.example.com", content)
        self.assertNotIn("new.example.com", content)
        self.assertIn("https://crt.sh/?id=15", content)
        self.assertEqual(self.invoke("report", "different.org", "--scan-id", "1")[0], 1)
        self.assertEqual(self.invoke("report", "example.com", "-o", str(self.db))[0], 1)
        self.assertEqual(self.invoke("history", "example.com")[0], 0)

    def test_partial_and_failed_scans_are_preserved(self):
        def reply(url, **kwargs):
            if "crt.sh" in url:
                return [{"id": 10, "name_value": "found.example.com"}]
            raise FetchError("Provider unavailable.")

        with patch("osintscope.http.HttpClient.get_json", side_effect=reply):
            code, listing, _ = self.invoke(
                "scan", "example.com", "--source", "ct", "--source", "pdns"
            )
            self.assertEqual(code, 3)
            self.assertIn("partial", listing)
            self.assertIn("found.example.com", self.invoke("report", "example.com")[1])
            self.assertEqual(self.invoke("scan", "example.com", "--source", "asn")[0], 1)
        report = json.loads(self.invoke("report", "example.com", "--format", "json")[1])
        self.assertEqual(report["summary"]["status"], "failed")
        self.assertTrue(report["comparison"]["unknown"])
        self.assertEqual(report["comparison"]["removed"], [])

    def test_arguments_and_empty_history(self):
        with self.assertRaises(SystemExit) as parser_error, redirect_stderr(io.StringIO()):
            main(["scan", "https://example.com"])
        self.assertEqual(parser_error.exception.code, 2)
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            main(["scan", "example.com", "--source", "made-up"])
        self.assertEqual(self.invoke("scan", "example.com", "--timeout", "nan")[0], 1)
        self.assertFalse(self.db.exists())
        self.assertIn("technology", self.invoke("sources")[1])
        self.assertFalse(self.db.exists())
        self.assertIn("No stored investigations", self.invoke("history", "example.com")[1])
        self.assertEqual(self.invoke("diff", "example.com")[0], 1)
        self.assertEqual(self.invoke("report", "example.com")[0], 1)
        self.assertEqual([c.key for c in select_collectors(["asn", "pdns"])], ["pdns", "asn"])

    def test_html_escapes_untrusted_text_and_references(self):
        scan = Investigation(
            1,
            "example.com",
            "now",
            "now",
            [
                Observation(
                    "technology",
                    "example.com",
                    "<script>alert(1)</script>",
                    "test",
                    "javascript:alert(1)",
                    "now",
                    {"product": "<img>"},
                ),
            ],
            [Coverage("test", "partial", "limited <script>")],
            [],
        )
        document = html_report(scan)
        self.assertIn("&lt;script&gt;", document)
        self.assertNotIn("<script>", document)
        self.assertNotIn('href="javascript:', document)
        self.assertIn("Source coverage is incomplete", document)

    def test_faulty_extension_cannot_replace_another_sources_coverage(self):
        ct = select_collectors(["ct"])[0]
        client = Mock()
        client.get_json.return_value = [{"id": 11, "name_value": "www.example.com"}]
        extension = Mock(key="extension", requires=())
        for coverage in [Coverage("ct", "complete"), Coverage("extension", "ok")]:
            extension.collect.return_value = CollectorResult("extension", [], [coverage])
            scan = investigate("example.com", client, [ct, extension])
            self.assertEqual(
                [(c.key, c.status) for c in scan.coverage],
                [("ct", "complete"), ("extension", "failed")],
            )
            self.assertTrue(scan.observations)
