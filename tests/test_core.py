import unittest
import json
import tempfile
from pathlib import Path

from vuln_intel_prioritizer.core import Vulnerability, load_vulns, prioritize, write_json, write_report


class VulnPrioritizerTests(unittest.TestCase):
    def test_exploited_external_critical_asset_ranks_first(self):
        items = [
            Vulnerability("CVE-low", 6.0, False, False, "medium", "wiki", "lower risk"),
            Vulnerability("CVE-high", 9.8, True, True, "critical", "vpn", "urgent", epss=0.9, kev_listed=True, public_exploit=True),
        ]

        ranked = prioritize(items)

        self.assertEqual(ranked[0]["cve"], "CVE-high")
        self.assertEqual(ranked[0]["priority_score"], 100)

    def test_epss_and_kev_contribute_to_explainable_score(self):
        item = prioritize([Vulnerability("CVE-x", 7.0, False, False, "medium", "host", "x", epss=0.8, kev_listed=True)])[0]
        self.assertEqual(item["score_breakdown"]["known_exploitation"], 25)
        self.assertEqual(item["score_breakdown"]["epss"], 12)

    def test_compensating_control_reduces_priority(self):
        base = Vulnerability("CVE-x", 8.0, False, True, "high", "host", "x")
        controlled = Vulnerability("CVE-y", 8.0, False, True, "high", "host", "y", compensating_control=True)
        ranked = {item["cve"]: item for item in prioritize([base, controlled])}
        self.assertEqual(ranked["CVE-x"]["priority_score"] - ranked["CVE-y"]["priority_score"], 10)

    def test_priority_score_never_becomes_negative(self):
        item = prioritize([Vulnerability("CVE-x", 0.0, False, False, "low", "host", "x", compensating_control=True)])[0]
        self.assertEqual(item["priority_score"], 0)

    def test_no_fix_changes_recommended_action(self):
        item = prioritize([Vulnerability("CVE-x", 8.0, False, False, "high", "host", "x", fix_available=False)])[0]
        self.assertIn("Mitigate", item["recommended_action"])

    def test_invalid_cvss_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vulns.json"
            path.write_text(json.dumps([{"cve": "CVE-x", "cvss": 11, "exploited": False, "internet_exposed": False, "asset_criticality": "low", "affected_asset": "x", "summary": "x"}]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CVSS"):
                load_vulns(path)

    def test_sample_data_has_multiple_risk_contexts(self):
        ranked = prioritize(load_vulns("sample_data/vulnerabilities.json"))
        self.assertEqual(len(ranked), 5)
        self.assertGreater(ranked[0]["priority_score"], ranked[-1]["priority_score"])

    def test_markdown_and_json_reports_are_generated(self):
        ranked = prioritize(load_vulns("sample_data/vulnerabilities.json"))
        with tempfile.TemporaryDirectory() as directory:
            markdown = Path(directory) / "report.md"
            output_json = Path(directory) / "report.json"
            write_report(ranked, markdown)
            write_json(ranked, output_json)
            parsed = json.loads(output_json.read_text(encoding="utf-8"))
            report = markdown.read_text(encoding="utf-8")
        self.assertEqual(len(parsed), 5)
        self.assertIn("Source", report)


if __name__ == "__main__":
    unittest.main()
