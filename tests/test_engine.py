"""
Additional coverage for cgull.engine.CGullScanner beyond what
test_scanner.py and the false-positive/suppression/parallel tests cover:
ignore-file loading, single-file targets, scan_text severity filtering,
AST-only engine mode, and the module-level parallel worker function.
"""

import os
import shutil
import tempfile
import time
import unittest

from cgull.engine import CGullScanner, _scan_file_worker
from cgull.models import AnalysisEngine, Severity, ScanError

VULNERABLE_CODE = "void f(char *b) {\n    gets(b);\n}\n"


def _blocking_scan_worker(
    file_path,
    config,
    profiles=None,
    quiet=False,
    progress_active=False,
):
    """Spawn-safe worker used to verify prompt process-pool interruption."""
    time.sleep(10)
    return [], 0, 0.0, "fallback-parser", "regex-fallback", "success", "LIMITED", None


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
            try:
                os.symlink(os.path.join(temp_dir, "does_not_exist_target"), broken_link)
            except OSError:
                self.skipTest("Symlinks not supported or permitted on this platform/privilege level")
            res_seq = CGullScanner().scan_path(temp_dir, jobs=1)
            res_par = CGullScanner().scan_path(temp_dir, jobs=2)

            for result in (res_seq, res_par):
                self.assertEqual(result.files_discovered, 2)  # both discovered
                self.assertEqual(result.files_analyzed, 1)    # good.c analyzed
                self.assertEqual(result.files_failed, 1)      # bad.c failed
                self.assertEqual(len(result.file_summaries), 2)  # summaries for both
                self.assertTrue(any("good.c" in fs.file_path for fs in result.file_summaries))
                self.assertEqual(len(result.scan_errors), 1)
                err = result.scan_errors[0]
                self.assertEqual(err.file_path, "bad.c")
                self.assertTrue(err.error_type)
                self.assertTrue(err.message)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestScanTextSeverityFilter(unittest.TestCase):
    def test_scan_text_applies_severity_filter(self):
        scanner = CGullScanner(severity_filter={Severity.HIGH})
        result = scanner.scan_text(VULNERABLE_CODE, "sample.c")
        for issue in result.issues:
            self.assertEqual(issue.impact, Severity.HIGH)

class TestSeverityFilterConsistency(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.code = """
#include <stdio.h>
#include <string.h>

void f(char *b) {
    gets(b); // HIGH: CGULL-001, CGULL-023
    for (int i = 0; i < strlen(b); i++) { // MEDIUM: CGULL-012 (if atoi/strlen)
        if (i == 42) goto done; // LOW: CGULL-018
    }
done:
    return;
}
"""
        self.f1 = os.path.join(self.temp_dir, "file1.c")
        with open(self.f1, "w") as f:
            f.write(self.code)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _assert_consistency(self, result):
        sum_file_issues = sum(fs.issues_count for fs in result.file_summaries)
        self.assertEqual(result.total_issues_count, len(result.issues))
        self.assertEqual(result.total_issues_count, sum_file_issues)
        for fs in result.file_summaries:
            self.assertEqual(fs.issues_count, fs.high_count + fs.medium_count + fs.low_count)

    def test_no_filter(self):
        scanner = CGullScanner()
        res = scanner.scan_path(self.temp_dir)
        self._assert_consistency(res)

    def test_high_only_filter(self):
        scanner = CGullScanner(severity_filter={Severity.HIGH})
        res = scanner.scan_path(self.temp_dir)
        self._assert_consistency(res)
        for issue in res.issues:
            self.assertEqual(issue.impact, Severity.HIGH)

    def test_medium_plus_filter(self):
        scanner = CGullScanner(severity_filter={Severity.HIGH, Severity.MEDIUM})
        res = scanner.scan_path(self.temp_dir)
        self._assert_consistency(res)
        for issue in res.issues:
            self.assertIn(issue.impact, {Severity.HIGH, Severity.MEDIUM})

    def test_low_plus_filter(self):
        scanner = CGullScanner(severity_filter={Severity.HIGH, Severity.MEDIUM, Severity.LOW})
        res = scanner.scan_path(self.temp_dir)
        self._assert_consistency(res)
        for issue in res.issues:
            self.assertIn(issue.impact, {Severity.HIGH, Severity.MEDIUM, Severity.LOW})

    def test_scan_text_filter_consistency(self):
        for sev_filter in [
            None,
            {Severity.HIGH},
            {Severity.HIGH, Severity.MEDIUM},
            {Severity.HIGH, Severity.MEDIUM, Severity.LOW},
        ]:
            scanner = CGullScanner(severity_filter=sev_filter)
            res = scanner.scan_text(self.code, "sample.c")
            self._assert_consistency(res)


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

    def test_regex_only_mode_reports_regex_parser_status(self):
        scanner = CGullScanner(engine_mode=AnalysisEngine.REGEX)
        result = scanner.scan_text(VULNERABLE_CODE, "sample.c")
        self.assertEqual(result.get_overall_parser_status(), "regex")

    def test_atomic_failure_policy_discards_findings_on_failed_file(self):
        temp_dir = tempfile.mkdtemp()
        try:
            broken_link = os.path.join(temp_dir, "bad.c")
            try:
                os.symlink(os.path.join(temp_dir, "nonexistent"), broken_link)
            except OSError:
                self.skipTest("Symlinks not supported")
            result = CGullScanner().scan_path(temp_dir)
            self.assertEqual(result.files_failed, 1)
            self.assertEqual(result.total_issues_count, 0)
            self.assertEqual(result.issues, [])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_rule_exception_fails_file_and_reports_scan_error(self):
        from cgull.rules.base import BaseRule
        class BuggyRule(BaseRule):
            rule_id = "BUGGY-001"
            name = "Buggy Rule"
            impact = Severity.LOW
            def scan_line(self, **kwargs):
                raise RuntimeError("Buggy rule crashed!")

        scanner = CGullScanner(rules=[BuggyRule()])
        result = scanner.scan_text("int main() { return 0; }", "app.c")
        self.assertEqual(result.files_failed, 1)
        self.assertEqual(result.get_overall_analysis_status(), "failed")
        self.assertEqual(len(result.scan_errors), 1)
        self.assertEqual(result.scan_errors[0].error_type, "RuntimeError")
        self.assertEqual(result.scan_errors[0].message, "Buggy rule crashed!")

    def test_rule_exception_logs_to_stderr_when_not_quiet(self):
        import io
        from unittest.mock import patch
        from cgull.rules.base import BaseRule

        class BuggyRule(BaseRule):
            rule_id = "BUGGY-001"
            name = "Buggy Rule"
            impact = Severity.LOW
            def scan_line(self, **kwargs):
                raise AttributeError("AttributeError in rule AST scan")

        scanner = CGullScanner(rules=[BuggyRule()])
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            result = scanner.scan_text("int main() { return 0; }", "app.c", quiet=False)

        self.assertEqual(result.files_failed, 1)
        output = stderr_buf.getvalue()
        self.assertIn("[ERROR] Analysis failed for app.c: AttributeError: AttributeError in rule AST scan", output)

    def test_stderr_error_logging_sanitizes_ansi_escapes_and_control_chars(self):
        import io
        from unittest.mock import patch
        from cgull.rules.base import BaseRule

        class MaliciousErrorRule(BaseRule):
            rule_id = "MAL-001"
            name = "Malicious Rule"
            impact = Severity.LOW
            def scan_line(self, **kwargs):
                raise RuntimeError("Exploit \x1b[2J\r\nInjected line")

        scanner = CGullScanner(rules=[MaliciousErrorRule()])
        stderr_buf = io.StringIO()
        file_path_with_escape = "bad_\x1b[31mfile\x1b[0m.c"
        with patch("sys.stderr", stderr_buf):
            scanner.scan_text("int main() { return 0; }", file_path_with_escape, quiet=False)

        output = stderr_buf.getvalue()
        self.assertNotIn("\x1b[2J", output)
        self.assertNotIn("\x1b[31m", output)
        self.assertNotIn("\r", output)
        self.assertIn("Analysis failed for bad_file.c: RuntimeError: Exploit  Injected line", output)

    def test_stderr_error_logging_adds_leading_newline_when_progress_active(self):
        import io
        from unittest.mock import patch
        from cgull.rules.base import BaseRule

        class BuggyRule(BaseRule):
            rule_id = "BUGGY-001"
            name = "Buggy Rule"
            impact = Severity.LOW
            def scan_line(self, **kwargs):
                raise RuntimeError("Crash during scan")

        temp_dir = tempfile.mkdtemp()
        try:
            f1 = os.path.join(temp_dir, "sample.c")
            with open(f1, "w") as f:
                f.write("int x = 0;")

            scanner = CGullScanner(rules=[BuggyRule()])
            stderr_buf = io.StringIO()
            def dummy_cb(c, t, p): pass

            with patch("sys.stderr", stderr_buf):
                scanner.scan_path(temp_dir, jobs=1, progress_callback=dummy_cb, quiet=False)

            output = stderr_buf.getvalue()
            self.assertTrue(output.startswith("\n[ERROR] Analysis failed for"))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_rule_exception_suppresses_stderr_when_quiet(self):
        import io
        from unittest.mock import patch
        from cgull.rules.base import BaseRule

        class BuggyRule(BaseRule):
            rule_id = "BUGGY-001"
            name = "Buggy Rule"
            impact = Severity.LOW
            def scan_line(self, **kwargs):
                raise AttributeError("AttributeError in rule AST scan")

        scanner = CGullScanner(rules=[BuggyRule()])
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            result = scanner.scan_text("int main() { return 0; }", "app.c", quiet=True)

        self.assertEqual(result.files_failed, 1)
        self.assertEqual(stderr_buf.getvalue(), "")

    def test_parallel_worker_exception_logs_to_stderr_when_not_quiet(self):
        import io
        from unittest.mock import patch, MagicMock
        from concurrent.futures import Future

        temp_dir = tempfile.mkdtemp()
        try:
            f1 = os.path.join(temp_dir, "crash.c")
            f2 = os.path.join(temp_dir, "good.c")
            with open(f1, "w") as f:
                f.write(VULNERABLE_CODE)
            with open(f2, "w") as f:
                f.write(VULNERABLE_CODE)

            def mock_submit(fn, file_path, config, *args, **kwargs):
                fut = Future()
                if "crash.c" in file_path:
                    fut.set_exception(AttributeError("AST node missing attribute"))
                else:
                    fut.set_result(fn(file_path, config, *args, **kwargs))
                return fut

            mock_pool = MagicMock()
            mock_pool.submit.side_effect = mock_submit

            scanner = CGullScanner()
            stderr_buf = io.StringIO()
            with patch("cgull.engine.ProcessPoolExecutor", return_value=mock_pool):
                with patch("sys.stderr", stderr_buf):
                    res = scanner.scan_path(temp_dir, jobs=2, quiet=False)

            self.assertEqual(res.files_failed, 1)
            output = stderr_buf.getvalue()
            self.assertIn("Analysis failed for", output)
            self.assertIn("crash.c: AttributeError: AST node missing attribute", output)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_parallel_worker_exception_suppresses_stderr_when_quiet(self):
        import io
        from unittest.mock import patch, MagicMock
        from concurrent.futures import Future

        temp_dir = tempfile.mkdtemp()
        try:
            f1 = os.path.join(temp_dir, "crash.c")
            f2 = os.path.join(temp_dir, "good.c")
            with open(f1, "w") as f:
                f.write(VULNERABLE_CODE)
            with open(f2, "w") as f:
                f.write(VULNERABLE_CODE)

            def mock_submit(fn, file_path, config, *args, **kwargs):
                fut = Future()
                if "crash.c" in file_path:
                    fut.set_exception(AttributeError("AST node missing attribute"))
                else:
                    fut.set_result(fn(file_path, config, *args, **kwargs))
                return fut

            mock_pool = MagicMock()
            mock_pool.submit.side_effect = mock_submit

            scanner = CGullScanner()
            stderr_buf = io.StringIO()
            with patch("cgull.engine.ProcessPoolExecutor", return_value=mock_pool):
                with patch("sys.stderr", stderr_buf):
                    res = scanner.scan_path(temp_dir, jobs=2, quiet=True)

            self.assertEqual(res.files_failed, 1)
            self.assertEqual(stderr_buf.getvalue(), "")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestParallelWorkerFunction(unittest.TestCase):
    def test_scan_file_worker_returns_same_shape_as_sequential(self):
        temp_dir = tempfile.mkdtemp()
        try:
            file_path = os.path.join(temp_dir, "sample.c")
            with open(file_path, "w") as f:
                f.write(VULNERABLE_CODE)
            issues, loc, duration_ms, parser_status, parse_tier, status, confidence, err = _scan_file_worker(file_path, AnalysisEngine.HYBRID)
            self.assertGreaterEqual(len(issues), 1)
            self.assertGreater(loc, 0)
            self.assertGreaterEqual(duration_ms, 0)
            self.assertIn(parser_status, ["pycparser-success", "fallback-parser"])
            self.assertIn(parse_tier, ["pcpp+pycparser", "directive-stripped", "regex-fallback"])
            self.assertEqual(status, "success")
            self.assertIn(confidence, ["FULL", "FALLBACK"])
            self.assertIsNone(err)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_scan_files_parallel_handles_keyboard_interrupt(self):
        from unittest.mock import patch
        temp_dir = tempfile.mkdtemp()
        try:
            f1 = os.path.join(temp_dir, "f1.c")
            f2 = os.path.join(temp_dir, "f2.c")
            with open(f1, "w") as f:
                f.write(VULNERABLE_CODE)
            with open(f2, "w") as f:
                f.write(VULNERABLE_CODE)

            scanner = CGullScanner()
            with patch("cgull.engine.as_completed", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    scanner.scan_path(temp_dir, jobs=2)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_parallel_interrupt_terminates_running_workers_promptly(self):
        from unittest.mock import patch
        temp_dir = tempfile.mkdtemp()
        try:
            f1 = os.path.join(temp_dir, "f1.c")
            f2 = os.path.join(temp_dir, "f2.c")
            with open(f1, "w") as f:
                f.write(VULNERABLE_CODE)
            with open(f2, "w") as f:
                f.write(VULNERABLE_CODE)

            scanner = CGullScanner()
            t0 = time.time()
            # Patch with a module-level function, not a MagicMock side effect.
            # ProcessPoolExecutor uses spawn on Windows, so submitted callables
            # must be importable and picklable in the child process.
            with patch("cgull.engine._scan_file_worker", new=_blocking_scan_worker):
                with patch("cgull.engine.as_completed", side_effect=KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        scanner.scan_path(temp_dir, jobs=2)
            elapsed = time.time() - t0
            self.assertLess(elapsed, 2.0, f"Interrupt took {elapsed:.2f}s; workers were not terminated promptly")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_parallel_worker_crash_records_scan_error_and_correct_scanned_count(self):
        from concurrent.futures import Future, ProcessPoolExecutor
        from unittest.mock import patch, MagicMock
        temp_dir = tempfile.mkdtemp()
        try:
            f1 = os.path.join(temp_dir, "good.c")
            f2 = os.path.join(temp_dir, "crash.c")
            with open(f1, "w") as f:
                f.write(VULNERABLE_CODE)
            with open(f2, "w") as f:
                f.write(VULNERABLE_CODE)

            def mock_submit(fn, file_path, config, *args, **kwargs):
                fut = Future()
                if "crash.c" in file_path:
                    fut.set_exception(RuntimeError("Simulated worker process crash"))
                else:
                    fut.set_result(fn(file_path, config, *args, **kwargs))
                return fut

            mock_pool = MagicMock()
            mock_pool.submit.side_effect = mock_submit

            scanner = CGullScanner()
            with patch("cgull.engine.ProcessPoolExecutor", return_value=mock_pool):
                res = scanner.scan_path(temp_dir, jobs=2)

            self.assertEqual(res.files_discovered, 2)
            self.assertEqual(res.files_analyzed, 1)
            self.assertEqual(res.files_failed, 1)
            self.assertEqual(res.scanned_files_count, 1)
            self.assertEqual(len(res.failed_paths), 1)
            self.assertTrue(any("crash.c" in p for p in res.failed_paths))
            self.assertEqual(len(res.scan_errors), 1)
            err = res.scan_errors[0]
            self.assertTrue("crash.c" in err.file_path)
            self.assertEqual(err.error_type, "RuntimeError")
            self.assertEqual(err.message, "Simulated worker process crash")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestAnalysisStatusAndScanCompleteness(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.f1 = os.path.join(self.temp_dir, "f1.c")
        self.f2 = os.path.join(self.temp_dir, "f2.c")
        with open(self.f1, "w") as f:
            f.write("void f(char *b) { gets(b); }\n")
        with open(self.f2, "w") as f:
            f.write("void g(void) { int x = 0; }\n")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_completeness_and_status_sequential_and_parallel(self):
        scanner = CGullScanner()
        res_seq = scanner.scan_path(self.temp_dir, custom_ignore_patterns=["f2.c"], jobs=1)
        res_par = scanner.scan_path(self.temp_dir, custom_ignore_patterns=["f2.c"], jobs=2)

        for res in (res_seq, res_par):
            self.assertEqual(res.files_discovered, 2)
            self.assertEqual(res.files_analyzed, 1)
            self.assertEqual(res.files_ignored, 1)
            self.assertEqual(res.files_failed, 0)
            self.assertIn("analysis", res.to_dict())
            self.assertIn("parser", res.to_dict()["analysis"])
            self.assertIn("status", res.to_dict()["analysis"])
            self.assertIn("status_counts", res.to_dict()["analysis"])
            self.assertEqual(res.to_dict()["summary"]["files_discovered"], 2)
            self.assertEqual(res.to_dict()["summary"]["files_analyzed"], 1)
            self.assertEqual(res.to_dict()["summary"]["files_ignored"], 1)
            self.assertEqual(res.to_dict()["summary"]["files_failed"], 0)
            for issue in res.issues:
                self.assertIsNotNone(issue.confidence)


class TestDirectoryTraversalWithNegation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

        # Create nested directory structure:
        # vendor/foo.c
        # vendor/crypto/other.c
        # vendor/crypto/secure_memcmp.c
        os.makedirs(os.path.join(self.temp_dir, "vendor", "crypto"))
        with open(os.path.join(self.temp_dir, "vendor", "foo.c"), "w") as f:
            f.write("void foo() {}")
        with open(os.path.join(self.temp_dir, "vendor", "crypto", "other.c"), "w") as f:
            f.write("void other() {}")
        with open(os.path.join(self.temp_dir, "vendor", "crypto", "secure_memcmp.c"), "w") as f:
            f.write("void secure_memcmp() { char b[10]; gets(b); }")

        with open(os.path.join(self.temp_dir, ".cgullignore"), "w") as f:
            f.write("vendor/\n!vendor/crypto/secure_memcmp.c\n")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scan_path_traverses_ignored_dir_to_include_negated_file(self):
        scanner = CGullScanner()
        result = scanner.scan_path(self.temp_dir)
        self.assertEqual(result.scanned_files_count, 1)
        scanned_files = [fs.file_path for fs in result.file_summaries]
        self.assertTrue(any("secure_memcmp.c" in p for p in scanned_files))
        self.assertFalse(any("foo.c" in p for p in scanned_files))
        self.assertFalse(any("other.c" in p for p in scanned_files))

    def test_scan_path_prunes_ignored_tree_without_traversing(self):
        git_dir = os.path.join(self.temp_dir, ".git", "objects", "pack")
        os.makedirs(git_dir)
        git_file = os.path.join(git_dir, "pack.c")
        with open(git_file, "w") as f:
            f.write("void dummy() {}")

        scanner = CGullScanner()
        result = scanner.scan_path(self.temp_dir)
        scanned_files = [fs.file_path for fs in result.file_summaries]
        self.assertFalse(any(".git" in p for p in scanned_files))
        self.assertNotIn(".git/objects/pack/pack.c", result.ignored_paths)

    def test_scan_path_with_embedded_double_star_negation(self):
        sub_dir = os.path.join(self.temp_dir, "vendor", "sub")
        os.makedirs(sub_dir)
        good_file = os.path.join(sub_dir, "good.c")
        with open(good_file, "w") as f:
            f.write("void good() { char b[10]; gets(b); }")

        with open(os.path.join(self.temp_dir, ".cgullignore"), "w") as f:
            f.write("vendor/\n!vendor/**.c\n")

        scanner = CGullScanner()
        result = scanner.scan_path(self.temp_dir)
        scanned_files = [fs.file_path for fs in result.file_summaries]
        self.assertTrue(any("good.c" in p for p in scanned_files))


class TestProgressCallback(unittest.TestCase):
    def test_scan_path_sequential_triggers_callback(self):
        temp_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(temp_dir, "f1.c"), "w") as f:
                f.write(VULNERABLE_CODE)
            with open(os.path.join(temp_dir, "f2.c"), "w") as f:
                f.write(VULNERABLE_CODE)

            calls = []
            def cb(completed, total, path):
                calls.append((completed, total, path))

            CGullScanner().scan_path(temp_dir, jobs=1, progress_callback=cb)
            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[0], (0, 2, ""))
            self.assertEqual(calls[-1][0], 2)
            self.assertEqual(calls[-1][1], 2)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_scan_path_parallel_triggers_callback(self):
        temp_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(temp_dir, "f1.c"), "w") as f:
                f.write(VULNERABLE_CODE)
            with open(os.path.join(temp_dir, "f2.c"), "w") as f:
                f.write(VULNERABLE_CODE)

            calls = []
            def cb(completed, total, path):
                calls.append((completed, total, path))

            CGullScanner().scan_path(temp_dir, jobs=2, progress_callback=cb)
            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[0], (0, 2, ""))
            self.assertEqual(calls[-1][0], 2)
            self.assertEqual(calls[-1][1], 2)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestIssueFilePathIsRelative(unittest.TestCase):
    """
    Regression test: Issue.file_path used to be left as the absolute
    scan-time path for directory scans (while FileScanSummary.file_path
    was already relative), which broke portability of saved reports --
    e.g. a baseline captured on one machine/checkout would never match
    fingerprints computed against another checkout's absolute paths.
    """

    def test_directory_scan_issue_file_path_is_relative(self):
        temp_dir = tempfile.mkdtemp()
        try:
            nested = os.path.join(temp_dir, "src")
            os.makedirs(nested)
            with open(os.path.join(nested, "vuln.c"), "w") as f:
                f.write(VULNERABLE_CODE)
            result = CGullScanner().scan_path(temp_dir)
            self.assertGreaterEqual(len(result.issues), 1)
            for issue in result.issues:
                self.assertFalse(os.path.isabs(issue.file_path))
                self.assertEqual(issue.file_path, os.path.join("src", "vuln.c"))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_issue_file_path_matches_file_summary_file_path(self):
        temp_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(temp_dir, "vuln.c"), "w") as f:
                f.write(VULNERABLE_CODE)
            result = CGullScanner().scan_path(temp_dir)
            summary_paths = {fs.file_path for fs in result.file_summaries}
            issue_paths = {i.file_path for i in result.issues}
            self.assertTrue(issue_paths.issubset(summary_paths))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestJobsParameter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        with open(os.path.join(self.temp_dir, "f1.c"), "w") as f:
            f.write(VULNERABLE_CODE)
        with open(os.path.join(self.temp_dir, "f2.c"), "w") as f:
            f.write(VULNERABLE_CODE)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_jobs_negative_value_raises_value_error(self):
        scanner = CGullScanner()
        with self.assertRaises(ValueError) as ctx:
            scanner.scan_path(self.temp_dir, jobs=-1)
        self.assertIn("Invalid jobs value", str(ctx.exception))

    def test_jobs_zero_resolves_and_scans(self):
        scanner = CGullScanner()
        res = scanner.scan_path(self.temp_dir, jobs=0)
        self.assertEqual(res.scanned_files_count, 2)

    def test_jobs_sequential_and_parallel(self):
        scanner = CGullScanner()
        res_seq = scanner.scan_path(self.temp_dir, jobs=1)
        res_par = scanner.scan_path(self.temp_dir, jobs=2)
        self.assertEqual(res_seq.scanned_files_count, 2)
        self.assertEqual(res_par.scanned_files_count, 2)


if __name__ == "__main__":
    unittest.main()
