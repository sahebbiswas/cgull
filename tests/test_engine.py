"""
Additional coverage for cgull.engine.CGullScanner beyond what
test_scanner.py and the false-positive/suppression/parallel tests cover:
ignore-file loading, single-file targets, scan_text severity filtering,
AST-only engine mode, and the module-level parallel worker function.
"""

import os
import shutil
import tempfile
import unittest

from cgull.engine import CGullScanner, _scan_file_worker
from cgull.models import AnalysisEngine, Severity

VULNERABLE_CODE = "void f(char *b) {\n    gets(b);\n}\n"


class TestScanPathSingleFile(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.file_path = os.path.join(self.temp_dir, "sample.c")
        with open(self.file_path, "w") as f:
            f.write(VULNERABLE_CODE)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scan_path_accepts_single_file_target(self):
        result = CGullScanner().scan_path(self.file_path)
        self.assertEqual(result.scanned_files_count, 1)
        self.assertGreaterEqual(result.total_issues_count, 1)

    def test_scan_path_single_file_matching_ignore_pattern_is_skipped(self):
        result = CGullScanner().scan_path(self.file_path, custom_ignore_patterns=["sample.c"])
        self.assertEqual(result.scanned_files_count, 0)
        self.assertEqual(len(result.ignored_paths), 1)

    def test_scan_path_with_explicit_ignore_file(self):
        ignore_path = os.path.join(self.temp_dir, "custom.ignore")
        with open(ignore_path, "w") as f:
            f.write("sample.c\n")
        result = CGullScanner().scan_path(self.file_path, ignore_file=ignore_path)
        self.assertEqual(result.scanned_files_count, 0)


class TestScanPathUnreadableFile(unittest.TestCase):
    def test_unreadable_file_is_skipped_not_fatal(self):
        temp_dir = tempfile.mkdtemp()
        try:
            good = os.path.join(temp_dir, "good.c")
            with open(good, "w") as f:
                f.write(VULNERABLE_CODE)
            # A broken symlink with a .c extension: os.walk() lists it
            # under `files`, but open() will raise FileNotFoundError.
            # The scanner should skip it rather than crash the whole scan.
            broken_link = os.path.join(temp_dir, "bad.c")
            os.symlink(os.path.join(temp_dir, "does_not_exist_target"), broken_link)
            result = CGullScanner().scan_path(temp_dir)
            self.assertEqual(result.scanned_files_count, 2)  # both discovered
            self.assertEqual(len(result.file_summaries), 1)  # only good.c actually scanned
            self.assertTrue(any("good.c" in fs.file_path for fs in result.file_summaries))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestScanTextSeverityFilter(unittest.TestCase):
    def test_scan_text_applies_severity_filter(self):
        scanner = CGullScanner(severity_filter={Severity.HIGH})
        result = scanner.scan_text(VULNERABLE_CODE, "sample.c")
        for issue in result.issues:
            self.assertEqual(issue.impact, Severity.HIGH)


class TestEngineModes(unittest.TestCase):
    def test_ast_only_mode_skips_regex_rules(self):
        # CGULL-001 (banned gets()) is a REGEX-engine rule; in pure AST
        # mode it must not fire even though the code contains gets().
        scanner = CGullScanner(engine_mode=AnalysisEngine.AST)
        result = scanner.scan_text(VULNERABLE_CODE, "sample.c")
        self.assertFalse(any(i.rule_id == "CGULL-001" for i in result.issues))

    def test_regex_only_mode_skips_ast_rules(self):
        # CGULL-020 (unused arguments) is an AST-engine rule; in pure
        # REGEX mode it must not fire.
        code = "int f(int unused_param) {\n    return 1;\n}\n"
        scanner = CGullScanner(engine_mode=AnalysisEngine.REGEX)
        result = scanner.scan_text(code, "sample.c")
        self.assertFalse(any(i.rule_id == "CGULL-020" for i in result.issues))


class TestParallelWorkerFunction(unittest.TestCase):
    def test_scan_file_worker_returns_same_shape_as_sequential(self):
        temp_dir = tempfile.mkdtemp()
        try:
            file_path = os.path.join(temp_dir, "sample.c")
            with open(file_path, "w") as f:
                f.write(VULNERABLE_CODE)
            issues, loc, duration_ms = _scan_file_worker(file_path, AnalysisEngine.HYBRID)
            self.assertGreaterEqual(len(issues), 1)
            self.assertGreater(loc, 0)
            self.assertGreaterEqual(duration_ms, 0)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
