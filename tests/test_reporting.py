"""Unit tests for investigation report generation and HTML safety."""

import unittest

from malware_scanner.reporting import generate_investigation_report, render_html_report


class ReportingTests(unittest.TestCase):
    def test_generate_and_render_report(self):
        inv = {
            "id": "inv-test-999",
            "file_path": "/path/to/<script>alert('xss')</script>.elf",
            "sha256": "112233445566",
            "file_size": 4096,
            "file_type": "application/x-executable-elf",
            "state": "analysis_complete",
            "severity": "critical",
            "automated_assessment": "malicious",
            "matched_rules": [
                {"id": "ruleset:backdoor", "strings": ["$cmd1"]}
            ],
            "analyst_verdict": "awaiting_review",
            "details": {}
        }
        ai_result = {
            "assessment": "malicious",
            "summary": "Detected reverse shell binary attempting C2 connection.",
            "confidence": 0.92,
            "confidence_basis": "Matched known backdoor signature and suspicious binary features.",
            "supporting_evidence": ["YARA match: backdoor", "ELF 64-bit architecture"],
            "contradicting_evidence": [],
            "indicators": ["192.168.1.100"],
            "limitations": ["Static analysis only"],
            "recommended_actions": ["Isolate host immediately", "Verify binary with sandbox"],
            "analysis_status": "complete"
        }

        report = generate_investigation_report(inv, ai_result)
        self.assertEqual(report["report_id"], "rep-inv-test-999")
        self.assertEqual(report["target"]["sha256"], "112233445566")
        self.assertEqual(report["ai_assessment"]["confidence"], 0.92)

        html_out = render_html_report(report)
        self.assertIn("malyz3r Investigation Report", html_out)
        self.assertIn("112233445566", html_out)
        self.assertIn("ruleset:backdoor", html_out)

        # Critical security check: XSS script tag is safely escaped!
        self.assertNotIn("<script>alert('xss')</script>", html_out)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html_out)


if __name__ == "__main__":
    unittest.main()
