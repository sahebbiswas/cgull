"""
Tests for header deduplication behavior in CGullScanner.
"""
import os
import tempfile
import unittest

from cgull.engine import CGullScanner
from cgull.models import ScanConfig

# A minimal vulnerability that triggers CGULL-001 (gets())
VULN_HEADER = """
#ifndef VULN_HEADER_H
#define VULN_HEADER_H

void vulnerable(char *b) {
    gets(b);  // HIGH: CGULL-001
}

#endif // VULN_HEADER_H
"""

# Two source files that include the same header
SOURCE_TEMPLATE = """
#include \"header.h\"

int main() {
    char buf[10];
    vulnerable(buf);
    return 0;
}
"""

class TestHeaderDeduplication(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory with header and two source files
        self.temp_dir = tempfile.mkdtemp()
        self.header_path = os.path.join(self.temp_dir, "header.h")
        with open(self.header_path, "w") as f:
            f.write(VULN_HEADER)
        # file1.c
        self.file1 = os.path.join(self.temp_dir, "file1.c")
        with open(self.file1, "w") as f:
            f.write(SOURCE_TEMPLATE)
        # file2.c
        self.file2 = os.path.join(self.temp_dir, "file2.c")
        with open(self.file2, "w") as f:
            f.write(SOURCE_TEMPLATE)

    def tearDown(self):
        # Cleanup the temporary directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_default_deduplication(self):
        """Header deduplication should collapse CGULL-001 findings from both TUs into a single issue.
        The issue's related_tus set must contain both source files.
        """
        scanner = CGullScanner()  # default config (dedup_headers=True)
        result = scanner.scan_path(self.temp_dir)
        # Filter for the header-originating rule (CGULL-001 gets() usage)
        gets_issues = [i for i in result.issues if i.rule_id == "CGULL-001"]
        # Expect exactly one deduplicated issue for the header finding
        self.assertEqual(len(gets_issues), 1)
        issue = gets_issues[0]
        # The issue should reference the header file (relative path) as its primary file_path
        self.assertTrue(issue.file_path.endswith("header.h"))
        # related_tus should contain both source files (relative paths)
        related = set(issue.related_tus)
        self.assertIn(os.path.relpath(self.file1, self.temp_dir), related)
        self.assertIn(os.path.relpath(self.file2, self.temp_dir), related)

    def test_no_deduplication_flag(self):
        """When deduplication of headers is disabled, each TU should report its own CGULL-001 issue.
        The primary file_path must remain the canonical header path, with the TU represented in related_tus.
        """
        config = ScanConfig.create(dedup_headers=False)
        scanner = CGullScanner(config=config)
        result = scanner.scan_path(self.temp_dir)
        # Filter for the header-originating rule (CGULL-001 gets() usage)
        gets_issues = [i for i in result.issues if i.rule_id == "CGULL-001"]
        # Expect at least two issues: one per .c TU that includes the header
        # (plus potentially one from scanning header.h directly)
        self.assertGreaterEqual(len(gets_issues), 2)
        # Verify that all issues retain the canonical header path as primary location
        for issue in gets_issues:
            self.assertTrue(issue.file_path.endswith("header.h"))
        # Verify that the including TUs are represented in related_tus
        all_related_tus = {tu for issue in gets_issues for tu in issue.related_tus}
        self.assertIn(os.path.relpath(self.file1, self.temp_dir), all_related_tus)
        self.assertIn(os.path.relpath(self.file2, self.temp_dir), all_related_tus)

    def test_header_multiple_findings_disambiguated(self):
        """If a header contains multiple identical vulnerabilities on different lines,
        deduplication must preserve both distinct occurrences while merging their related_tus.
        """
        multi_header = """
#ifndef MULTI_HEADER_H
#define MULTI_HEADER_H

void f1(char *b) {
    gets(b);
}

void f2(char *b) {
    gets(b);
}

#endif
"""
        with open(self.header_path, "w") as f:
            f.write(multi_header)

        scanner = CGullScanner()  # dedup_headers=True
        result = scanner.scan_path(self.temp_dir)
        gets_issues = [i for i in result.issues if i.rule_id == "CGULL-001"]
        # Should have 2 distinct deduplicated issues (for the 2 distinct lines in header.h)
        self.assertEqual(len(gets_issues), 2)
        # Both issues share the same fingerprint since rule, relpath, and snippet are identical
        self.assertEqual(gets_issues[0].fingerprint, gets_issues[1].fingerprint)
        # But their line numbers are distinct
        self.assertNotEqual(gets_issues[0].line_number, gets_issues[1].line_number)
        # And both have both TUs in related_tus
        for issue in gets_issues:
            self.assertTrue(issue.file_path.endswith("header.h"))
            self.assertIn(os.path.relpath(self.file1, self.temp_dir), issue.related_tus)
            self.assertIn(os.path.relpath(self.file2, self.temp_dir), issue.related_tus)

    def test_sarif_header_location_preserved_when_dedup_disabled(self):
        """SARIF report must maintain the canonical header URI and region coordinates
        even when dedup_headers=False, surfacing the including TU in relatedTUs property.
        """
        import json
        from cgull.reporter import ReportGenerator
        config = ScanConfig.create(dedup_headers=False)
        scanner = CGullScanner(config=config)
        result = scanner.scan_path(self.temp_dir)
        sarif_str = ReportGenerator.to_sarif(result)
        sarif_obj = json.loads(sarif_str)
        results = [r for r in sarif_obj["runs"][0]["results"] if r["ruleId"] == "CGULL-001"]
        self.assertGreaterEqual(len(results), 2)
        including_tus = set()
        for r in results:
            uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertTrue(uri.endswith("header.h"))
            for tu in r["properties"].get("relatedTUs", []):
                including_tus.add(tu)
        self.assertIn(os.path.relpath(self.file1, self.temp_dir), including_tus)
        self.assertIn(os.path.relpath(self.file2, self.temp_dir), including_tus)

    def test_fingerprint_checkout_location_independence(self):
        """Fingerprints must depend only on rule_id, project-relative canonical path, and normalized snippet,
        making them identical regardless of checkout location or absolute path.
        """
        from cgull.utils import compute_issue_fingerprint
        scanner = CGullScanner()
        result = scanner.scan_path(self.temp_dir)
        gets_issue = next(i for i in result.issues if i.rule_id == "CGULL-001")
        expected_fp = compute_issue_fingerprint("CGULL-001", "header.h", gets_issue.code_snippet)
        self.assertEqual(gets_issue.fingerprint, expected_fp)

if __name__ == "__main__":
    unittest.main()
