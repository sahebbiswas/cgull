"""
Tests for cgull.baseline: fingerprint computation stability, baseline
loading/error-handling, and multiset-aware diffing.
"""

import json
import os
import shutil
import tempfile
import unittest
from collections import Counter

from cgull.engine import CGullScanner
from cgull.baseline import load_baseline_fingerprints, apply_baseline, BaselineError
from cgull.models import ScanError
from cgull.reporter import ReportGenerator
from cgull.utils import compute_issue_fingerprint

VULNERABLE_CODE = "#pragma once\nvoid f(char *b) {\n    gets(b);\n}\n"


class TestFingerprintStability(unittest.TestCase):
    def test_same_inputs_produce_same_fingerprint(self):
        fp1 = compute_issue_fingerprint("CGULL-001", "app.c", "gets(buf);")
        fp2 = compute_issue_fingerprint("CGULL-001", "app.c", "gets(buf);")
        self.assertEqual(fp1, fp2)

    def test_different_rule_id_produces_different_fingerprint(self):
        fp1 = compute_issue_fingerprint("CGULL-001", "app.c", "gets(buf);")
        fp2 = compute_issue_fingerprint("CGULL-002", "app.c", "gets(buf);")
        self.assertNotEqual(fp1, fp2)

    def test_different_file_produces_different_fingerprint(self):
        fp1 = compute_issue_fingerprint("CGULL-001", "app.c", "gets(buf);")
        fp2 = compute_issue_fingerprint("CGULL-001", "other.c", "gets(buf);")
        self.assertNotEqual(fp1, fp2)

    def test_whitespace_only_reformatting_does_not_change_fingerprint(self):
        fp1 = compute_issue_fingerprint("CGULL-001", "app.c", "gets(buf);")
        fp2 = compute_issue_fingerprint("CGULL-001", "app.c", "  gets(buf);  ")
        fp3 = compute_issue_fingerprint("CGULL-001", "app.c", "gets(buf)  ;")
        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)  # internal whitespace change IS significant here (different token spacing)

    def test_windows_path_normalized_same_as_forward_slash(self):
        fp1 = compute_issue_fingerprint("CGULL-001", "src/app.c", "gets(buf);")
        fp2 = compute_issue_fingerprint("CGULL-001", "src\\app.c", "gets(buf);")
        self.assertEqual(fp1, fp2)

    def test_tu_fingerprint_ignores_line_numbers(self):
        from cgull.utils import compute_issue_fingerprint_tu
        fp_line10 = compute_issue_fingerprint_tu("CGULL-001", "include/header.h", 10, "gets(buf);")
        fp_line50 = compute_issue_fingerprint_tu("CGULL-001", "include/header.h", 50, "gets(buf);")
        fp_standard = compute_issue_fingerprint("CGULL-001", "include/header.h", "gets(buf);")
        fp_no_line = compute_issue_fingerprint_tu("CGULL-001", "include/header.h", "gets(buf);")
        self.assertEqual(fp_line10, fp_line50)
        self.assertEqual(fp_line10, fp_standard)
        self.assertEqual(fp_line10, fp_no_line)

    def test_scanned_issues_have_nonempty_fingerprints(self):
        result = CGullScanner().scan_text(VULNERABLE_CODE, "app.c")
        self.assertTrue(all(i.fingerprint for i in result.issues))


class TestLoadBaselineFingerprints(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write(self, name, content):
        path = os.path.join(self.temp_dir, name)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_missing_file_raises_baseline_error(self):
        with self.assertRaises(BaselineError):
            load_baseline_fingerprints(os.path.join(self.temp_dir, "nope.json"))

    def test_invalid_json_raises_baseline_error(self):
        path = self._write("bad.json", "not json")
        with self.assertRaises(BaselineError):
            load_baseline_fingerprints(path)

    def test_valid_json_without_issues_key_raises_baseline_error(self):
        path = self._write("bad2.json", json.dumps({"foo": "bar"}))
        with self.assertRaises(BaselineError):
            load_baseline_fingerprints(path)

    def test_valid_report_loads_fingerprint_counts(self):
        result = CGullScanner().scan_text(VULNERABLE_CODE, "app.c")
        path = self._write("baseline.json", ReportGenerator.to_json(result))
        counts, rules_count = load_baseline_fingerprints(path)
        self.assertIsInstance(counts, Counter)
        self.assertEqual(sum(counts.values()), len(result.issues))
        self.assertEqual(rules_count, result.rules_applied)

    def test_issues_missing_fingerprint_key_are_skipped_not_fatal(self):
        # Defensive: a hand-edited or older-format baseline file might have
        # an issue entry with no fingerprint; it should be ignored rather
        # than crash the whole load.
        path = self._write("baseline.json", json.dumps({"issues": [{"rule_id": "CGULL-001"}]}))
        counts, rules_count = load_baseline_fingerprints(path)
        self.assertEqual(sum(counts.values()), 0)
        self.assertIsNone(rules_count)


class TestApplyBaseline(unittest.TestCase):
    def test_identical_scan_against_its_own_baseline_has_zero_new(self):
        result = CGullScanner().scan_text(VULNERABLE_CODE, "app.c")
        baseline_counts = Counter(i.fingerprint for i in result.issues)
        diffed = apply_baseline(result, baseline_counts)
        self.assertEqual(diffed.baseline_new_count, 0)
        self.assertEqual(diffed.baseline_resolved_count, 0)
        self.assertEqual(len(diffed.issues), 0)

    def test_empty_baseline_reports_everything_as_new(self):
        result = CGullScanner().scan_text(VULNERABLE_CODE, "app.c")
        diffed = apply_baseline(result, Counter())
        self.assertEqual(diffed.baseline_new_count, len(result.issues))

    def test_fixed_issue_counted_as_resolved(self):
        vulnerable = CGullScanner().scan_text(VULNERABLE_CODE, "app.c")
        baseline_counts = Counter(i.fingerprint for i in vulnerable.issues)
        clean = CGullScanner().scan_text("#pragma once\nvoid f(char *b, size_t n) {\n    fgets(b, n, stdin);\n}\n", "app.c")
        diffed = apply_baseline(clean, baseline_counts)
        self.assertEqual(diffed.baseline_new_count, 0)
        self.assertEqual(diffed.baseline_resolved_count, len(vulnerable.issues))

    def test_duplicate_fingerprint_multiset_diff(self):
        # Two identical-looking findings on two different lines share a
        # fingerprint; a second occurrence beyond what the baseline had
        # must still be recognized as new (not silently absorbed by a
        # plain set-membership check).
        one_call = CGullScanner().scan_text("void f(char *a) {\n    gets(a);\n}\n", "app.c")
        two_calls = CGullScanner().scan_text("void f(char *a, char *b) {\n    gets(a);\n    gets(b);\n}\n", "app.c")
        baseline_counts = Counter(i.fingerprint for i in one_call.issues)
        diffed = apply_baseline(two_calls, baseline_counts)
        gets_new = [i for i in diffed.issues if i.rule_id == "CGULL-001"]
        self.assertEqual(len(gets_new), 1)

    def test_result_fields_marked_as_baseline_filtered(self):
        result = CGullScanner().scan_text(VULNERABLE_CODE, "app.c")
        diffed = apply_baseline(result, Counter())
        self.assertTrue(diffed.is_baseline_filtered)
        self.assertEqual(diffed.baseline_total_before_filter, result.total_issues_count)

    def test_severity_counts_recomputed_for_filtered_result(self):
        code = "void f(char *a) {\n    gets(a);\n}\nvoid g(void) {\n    char buf[4096];\n}\n"
        result = CGullScanner().scan_text(code, "app.c")
        # Baseline already knows about both findings from g() (the magic
        # number and the uninitialized-array declaration); only the
        # gets() call in f() should show up as new.
        baseline_counts = Counter(
            i.fingerprint for i in result.issues if i.rule_id != "CGULL-001"
        )
        diffed = apply_baseline(result, baseline_counts)
        self.assertEqual([i.rule_id for i in diffed.issues], ["CGULL-001"])
        self.assertEqual(diffed.high_severity_count, 1)
        self.assertEqual(diffed.medium_severity_count, 0)


class TestBaselineToDictSerialization(unittest.TestCase):
    def test_baseline_summary_present_only_when_filtered(self):
        result = CGullScanner().scan_text(VULNERABLE_CODE, "app.c")
        self.assertNotIn("baseline", result.to_dict()["summary"])
        diffed = apply_baseline(result, Counter(), baseline_rules_count=20)
        summary_dict = diffed.to_dict()["summary"]
        self.assertIn("baseline", summary_dict)
        self.assertEqual(summary_dict["baseline"]["rules_applied_count"], 20)

    def test_apply_baseline_preserves_scan_completeness_and_analysis_metadata(self):
        result = CGullScanner().scan_text(VULNERABLE_CODE, "app.c")
        err = ScanError(file_path="failed.c", error_type="PermissionError", message="Permission denied")
        result.scan_errors = [err]
        result.failed_paths = ["failed.c"]
        result.files_discovered = 5
        result.files_analyzed = 3
        result.files_ignored = 1
        result.files_failed = 1
        result.analysis_status_counts = {"pycparser-success": 3, "parse-failed": 1}

        diffed = apply_baseline(result, Counter())
        self.assertEqual(diffed.scan_errors, [err])
        self.assertEqual(diffed.failed_paths, ["failed.c"])
        self.assertEqual(diffed.files_discovered, 5)
        self.assertEqual(diffed.files_analyzed, 3)
        self.assertEqual(diffed.files_ignored, 1)
        self.assertEqual(diffed.files_failed, 1)
        self.assertEqual(diffed.analysis_status_counts, {"pycparser-success": 3, "parse-failed": 1})


if __name__ == "__main__":
    unittest.main()
