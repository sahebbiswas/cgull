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
        """
        config = ScanConfig.create(dedup_headers=False)
        scanner = CGullScanner(config=config)
        result = scanner.scan_path(self.temp_dir)
        # Filter for the header-originating rule (CGULL-001 gets() usage)
        gets_issues = [i for i in result.issues if i.rule_id == "CGULL-001"]
        # Expect at least two issues: one per .c TU that includes the header
        # (plus potentially one from scanning header.h directly)
        self.assertGreaterEqual(len(gets_issues), 2)
        # Verify that at least the two .c source files are represented
        file_paths = {issue.file_path for issue in gets_issues}
        self.assertIn(os.path.relpath(self.file1, self.temp_dir), file_paths)
        self.assertIn(os.path.relpath(self.file2, self.temp_dir), file_paths)

if __name__ == "__main__":
    unittest.main()
