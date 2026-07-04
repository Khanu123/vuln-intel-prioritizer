import unittest

from vuln_intel_prioritizer.core import Vulnerability, prioritize


class VulnPrioritizerTests(unittest.TestCase):
    def test_exploited_external_critical_asset_ranks_first(self):
        items = [
            Vulnerability("CVE-low", 6.0, False, False, "medium", "wiki", "lower risk"),
            Vulnerability("CVE-high", 9.8, True, True, "critical", "vpn", "urgent"),
        ]

        ranked = prioritize(items)

        self.assertEqual(ranked[0]["cve"], "CVE-high")
        self.assertEqual(ranked[0]["priority_score"], 100)


if __name__ == "__main__":
    unittest.main()
