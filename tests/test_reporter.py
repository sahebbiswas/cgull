"""
Tests for cgull.reporter.ReportGenerator across all four output formats.
"""

import json
import unittest

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.reporter import ReportGenerator


VULNERABLE_CODE = """
#include <stdio.h>
void f(char *src) {
    char buf[32];
    gets(buf);
}
"""

CLEAN_CODE = """
void noop(void) {
    int total = 0;
    total = total + 1;
}
"""


class TestReportGeneratorJSON(unittest.TestCase):
    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_json_pretty_by_default(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_json(result)
        self.assertIn("\n", output)  # pretty-printed has newlines/indentation

    def test_json_compact_when_not_pretty(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_json(result, pretty=False)
        parsed = json.loads(output)
        self.assertIn("issues", parsed)

    def test_json_roundtrips_issue_fields(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        parsed = json.loads(ReportGenerator.to_json(result))
        self.assertGreaterEqual(len(parsed["issues"]), 1)
        issue = parsed["issues"][0]
        for key in ("rule_id", "rule_name", "impact", "file_path", "line_number", "message", "cwe_id"):
            self.assertIn(key, issue)

    def test_json_clean_file_has_no_issues(self):
        result = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        parsed = json.loads(ReportGenerator.to_json(result))
        self.assertEqual(parsed["summary"]["total_issues_count"], 0)
        self.assertEqual(parsed["issues"], [])


class TestReportGeneratorSARIF(unittest.TestCase):
    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_sarif_schema_fields_present(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertIn("$schema", parsed)
        self.assertEqual(len(parsed["runs"]), 1)

    def test_sarif_severity_maps_to_correct_level(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        levels = {r["level"] for r in parsed["runs"][0]["results"]}
        # CGULL-001 (gets) is High severity -> SARIF "error"
        self.assertIn("error", levels)

    def test_sarif_rules_deduplicated_across_multiple_findings(self):
        code = "void f(char *a, char *b, char *c) {\n    gets(a);\n    gets(b);\n    gets(c);\n}"
        result = self.scanner.scan_text(code, "sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        gets_rule_entries = [r for r in parsed["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "CGULL-001"]
        self.assertEqual(len(gets_rule_entries), 1)
        gets_results = [r for r in parsed["runs"][0]["results"] if r["ruleId"] == "CGULL-001"]
        self.assertEqual(len(gets_results), 3)

    def test_sarif_no_findings_produces_empty_results(self):
        result = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        self.assertEqual(parsed["runs"][0]["results"], [])

    def test_sarif_location_uses_forward_slashes(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "windows\\style\\sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        uri = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertNotIn("\\", uri)

    def test_sarif_results_include_partial_fingerprints(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        fp = parsed["runs"][0]["results"][0]["partialFingerprints"]["cgullFingerprint/v1"]
        self.assertTrue(fp)
        self.assertEqual(fp, result.issues[0].fingerprint)


class TestReportGeneratorMarkdown(unittest.TestCase):
    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_markdown_clean_scan_shows_passed_message(self):
        result = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        output = ReportGenerator.to_markdown(result)
        self.assertIn("No vulnerabilities detected", output)
        self.assertIn("✅ Passed", output)

    def test_markdown_vulnerable_scan_shows_findings(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_markdown(result)
        self.assertIn("CGULL-001", output)
        self.assertIn("Needs Immediate Remediation", output)

    def test_markdown_includes_autofix_block_when_present(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_markdown(result)
        self.assertIn("Suggested Fix", output)


class TestReportGeneratorTerminal(unittest.TestCase):
    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_terminal_clean_scan_shows_success(self):
        result = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        output = ReportGenerator.to_terminal_text(result)
        self.assertIn("No vulnerabilities found", output)

    def test_terminal_vulnerable_scan_shows_finding_details(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_terminal_text(result)
        self.assertIn("CGULL-001", output)
        self.assertIn("[HIGH]", output)

    def test_terminal_summary_counts_match_result(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_terminal_text(result)
        self.assertIn(f"Total Findings   : {result.total_issues_count}", output)


if __name__ == "__main__":
    unittest.main()
