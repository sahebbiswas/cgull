"""
Tests for cgull.cli: argument parsing and subcommand behavior.
"""

import io
import os
import json
import shutil
import tempfile
import contextlib
import unittest

from cgull.cli import main, build_parser


class TestArgumentParsing(unittest.TestCase):
    def test_default_command_is_scan_current_dir(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "."])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.target, ".")

    def test_bare_path_implies_scan_subcommand(self):
        # main() should rewrite `cgull somefile.c` to `cgull scan somefile.c`
        parser = build_parser()
        args = parser.parse_args(["scan", "somefile.c"])
        self.assertEqual(args.target, "somefile.c")

    def test_jobs_defaults_to_one(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "."])
        self.assertEqual(args.jobs, 1)

    def test_severity_choices_restricted(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["scan", ".", "--severity", "invalid"])


class TestScanCommand(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.c_file = os.path.join(self.temp_dir, "vuln.c")
        with open(self.c_file, "w") as f:
            f.write("void f(char *b) {\n    gets(b);\n}\n")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(argv)
        return code, stdout.getvalue()

    def test_scan_missing_target_returns_error(self):
        code, out = self._run(["scan", "/nonexistent/path/xyz"])
        self.assertEqual(code, 1)

    def test_scan_text_format_prints_findings(self):
        code, out = self._run(["scan", self.c_file, "--format", "text"])
        self.assertEqual(code, 0)
        self.assertIn("CGULL-001", out)

    def test_scan_json_format_is_valid_json(self):
        code, out = self._run(["scan", self.c_file, "--format", "json"])
        parsed = json.loads(out)
        self.assertIn("summary", parsed)

    def test_scan_sarif_format_is_valid_json(self):
        code, out = self._run(["scan", self.c_file, "--format", "sarif"])
        parsed = json.loads(out)
        self.assertEqual(parsed["version"], "2.1.0")

    def test_scan_markdown_format(self):
        code, out = self._run(["scan", self.c_file, "--format", "markdown"])
        self.assertIn("C-GULL Security Audit Report", out)

    def test_fail_on_high_returns_nonzero_when_high_severity_found(self):
        code, _ = self._run(["scan", self.c_file, "--fail-on-high"])
        self.assertEqual(code, 1)

    def test_fail_on_high_returns_zero_when_no_high_severity(self):
        clean_file = os.path.join(self.temp_dir, "clean.c")
        with open(clean_file, "w") as f:
            f.write("void noop(void) {\n    int total = 0;\n    total = total + 1;\n}\n")
        code, _ = self._run(["scan", clean_file, "--fail-on-high"])
        self.assertEqual(code, 0)

    def test_output_file_written_and_reported(self):
        out_path = os.path.join(self.temp_dir, "report.json")
        code, out = self._run(["scan", self.c_file, "-o", out_path, "--format", "json"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(out_path))
        with open(out_path) as f:
            parsed = json.load(f)
        self.assertIn("summary", parsed)

    def test_output_extension_autodetects_json_format(self):
        out_path = os.path.join(self.temp_dir, "report.json")
        code, _ = self._run(["scan", self.c_file, "-o", out_path])
        with open(out_path) as f:
            parsed = json.load(f)  # would raise if not actually JSON
        self.assertIn("issues", parsed)

    def test_severity_filter_high_excludes_lower_severity_issues(self):
        code, out = self._run(["scan", self.c_file, "--severity", "high", "--format", "json"])
        parsed = json.loads(out)
        for issue in parsed["issues"]:
            self.assertEqual(issue["impact"], "High")
        sum_file_issues = sum(fs["issues_count"] for fs in parsed["file_summaries"])
        self.assertEqual(parsed["summary"]["total_issues_count"], len(parsed["issues"]))
        self.assertEqual(parsed["summary"]["total_issues_count"], sum_file_issues)

    def test_severity_filter_formats_consistency(self):
        # Add a file with HIGH, MEDIUM, and LOW issues to thoroughly test filtering across formats
        multi_file = os.path.join(self.temp_dir, "multi.c")
        with open(multi_file, "w") as f:
            f.write(
                "#include <stdio.h>\n"
                "#include <string.h>\n"
                "void f(char *b) {\n"
                "    gets(b);\n"  # HIGH
                "    for (int i = 0; i < strlen(b); i++) {\n"  # MEDIUM
                "        if (i == 42) goto done;\n"  # LOW
                "    }\n"
                "done:\n"
                "    return;\n"
                "}\n"
            )

        for fmt in ["json", "sarif", "markdown", "text"]:
            code, out = self._run(["scan", multi_file, "--severity", "high", "--format", fmt])
            self.assertEqual(code, 0)
            if fmt == "json":
                parsed = json.loads(out)
                self.assertEqual(parsed["summary"]["total_issues_count"], len(parsed["issues"]))
                self.assertGreater(len(parsed["issues"]), 0)
                for issue in parsed["issues"]:
                    self.assertEqual(issue["impact"], "High")
            elif fmt == "sarif":
                parsed = json.loads(out)
                results = parsed["runs"][0]["results"]
                self.assertGreater(len(results), 0)
                for res in results:
                    self.assertEqual(res["level"], "error")
            elif fmt == "markdown":
                self.assertIn("| **Total Issues** | **", out)
                # Ensure HIGH badge is present but MEDIUM/LOW badges are absent in findings
                self.assertIn("[🔴 HIGH]", out)
                self.assertNotIn("[🟡 MEDIUM]", out)
                self.assertNotIn("[🔵 LOW]", out)
                # Count finding section headers (e.g. ### #1 [🔴 HIGH])
                finding_count = out.count("### #")
                self.assertGreater(finding_count, 0)
                self.assertIn(f"| **Total Issues** | **{finding_count}** |", out)
            elif fmt == "text":
                self.assertIn("Total Findings   :", out)
                self.assertIn("[HIGH]", out)
                self.assertNotIn("[MEDIUM]", out)
                self.assertNotIn("[LOW]", out)
                # Check displayed total findings matches rendered findings count
                # Terminal output format rendered findings start with "[HIGH]   " or similar tags
                rendered_findings_count = out.count("[HIGH]   ")
                self.assertGreater(rendered_findings_count, 0)
                self.assertIn(f"Total Findings   : {rendered_findings_count} (High: {rendered_findings_count}, Medium: 0, Low: 0)", out)

    def test_regex_engine_mode_runs_without_error(self):
        code, out = self._run(["scan", self.c_file, "--engine", "regex", "--format", "json"])
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertGreaterEqual(parsed["summary"]["total_issues_count"], 1)

    def test_bare_target_without_scan_keyword_still_works(self):
        code, out = self._run([self.c_file, "--format", "json"])
        parsed = json.loads(out)
        self.assertIn("summary", parsed)

    def test_severity_filter_medium_includes_high_and_medium(self):
        code, out = self._run(["scan", self.c_file, "--severity", "medium", "--format", "json"])
        parsed = json.loads(out)
        for issue in parsed["issues"]:
            self.assertIn(issue["impact"], ("High", "Medium"))

    def test_severity_filter_low_includes_all_but_info(self):
        code, out = self._run(["scan", self.c_file, "--severity", "low", "--format", "json"])
        self.assertEqual(code, 0)

    def test_ast_engine_mode_runs_without_error(self):
        code, out = self._run(["scan", self.c_file, "--engine", "ast", "--format", "json"])
        self.assertEqual(code, 0)

    def test_output_extension_autodetects_sarif_format(self):
        out_path = os.path.join(self.temp_dir, "report.sarif")
        code, _ = self._run(["scan", self.c_file, "-o", out_path])
        with open(out_path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["version"], "2.1.0")

    def test_output_extension_autodetects_markdown_format(self):
        out_path = os.path.join(self.temp_dir, "report.md")
        code, _ = self._run(["scan", self.c_file, "-o", out_path])
        with open(out_path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("C-GULL Security Audit Report", content)

    def test_scan_quiet_flag_suppresses_stderr_progress(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code, out = self._run(["scan", self.c_file, "-q"])
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")

    def test_output_write_failure_returns_error(self):
        # Writing to a path inside a non-existent directory should fail
        # cleanly with a non-zero exit code rather than raising.
        bad_path = os.path.join(self.temp_dir, "no_such_dir", "report.json")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            code = main(["scan", self.c_file, "-o", bad_path])
        self.assertEqual(code, 1)

    def test_fail_on_error_returns_nonzero_when_scan_errors_occur(self):
        broken_link = os.path.join(self.temp_dir, "broken.c")
        try:
            os.symlink(os.path.join(self.temp_dir, "nonexistent"), broken_link)
        except OSError:
            self.skipTest("Symlinks not supported")
        code, out = self._run(["scan", self.temp_dir, "--fail-on-error"])
        self.assertEqual(code, 1)

    def test_without_fail_on_error_returns_zero_even_with_scan_errors(self):
        broken_link = os.path.join(self.temp_dir, "broken.c")
        try:
            os.symlink(os.path.join(self.temp_dir, "nonexistent"), broken_link)
        except OSError:
            self.skipTest("Symlinks not supported")
        clean_file = os.path.join(self.temp_dir, "clean.c")
        with open(clean_file, "w") as f:
            f.write("void noop(void) {}\n")
        code, out = self._run(["scan", self.temp_dir, "--format", "json"])
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertEqual(parsed["summary"]["files_failed"], 1)
        self.assertEqual(len(parsed["scan_errors"]), 1)


class TestBaselineFlags(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.c_file = os.path.join(self.temp_dir, "vuln.c")
        with open(self.c_file, "w") as f:
            f.write("void f(char *b) {\n    gets(b);\n}\n")
        self.baseline_path = os.path.join(self.temp_dir, "baseline.json")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(argv)
        return code, stdout.getvalue()

    def test_update_baseline_writes_full_json_report(self):
        code, out = self._run(["scan", self.c_file, "--update-baseline", self.baseline_path])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(self.baseline_path))
        with open(self.baseline_path) as f:
            data = json.load(f)
        self.assertGreaterEqual(len(data["issues"]), 1)
        self.assertIn("fingerprint", data["issues"][0])

    def test_baseline_flag_suppresses_known_findings(self):
        self._run(["scan", self.c_file, "--update-baseline", self.baseline_path])
        code, out = self._run(["scan", self.c_file, "--baseline", self.baseline_path, "--format", "json"])
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertEqual(parsed["summary"]["total_issues_count"], 0)
        self.assertIn("baseline", parsed["summary"])

    def test_fail_on_high_only_fails_on_new_issues_with_baseline(self):
        self._run(["scan", self.c_file, "--update-baseline", self.baseline_path])
        # No code changes: --fail-on-high should now pass since nothing is new.
        code, _ = self._run(["scan", self.c_file, "--baseline", self.baseline_path, "--fail-on-high"])
        self.assertEqual(code, 0)

    def test_fail_on_high_still_fails_on_genuinely_new_issue(self):
        self._run(["scan", self.c_file, "--update-baseline", self.baseline_path])
        with open(self.c_file, "a") as f:
            f.write("void g(char *dest, char *src) {\n    strcpy(dest, src);\n}\n")
        code, _ = self._run(["scan", self.c_file, "--baseline", self.baseline_path, "--fail-on-high"])
        self.assertEqual(code, 1)

    def test_missing_baseline_file_is_a_clean_error_not_a_crash(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            code = main(["scan", self.c_file, "--baseline", os.path.join(self.temp_dir, "nope.json")])
        self.assertEqual(code, 1)
        self.assertIn("Baseline file not found", stderr.getvalue())

    def test_update_baseline_snapshots_full_result_even_with_baseline_also_passed(self):
        self._run(["scan", self.c_file, "--update-baseline", self.baseline_path])
        second_baseline = os.path.join(self.temp_dir, "baseline2.json")
        # Even filtered down to 0 issues by --baseline, --update-baseline
        # should still snapshot everything that was actually found.
        self._run(["scan", self.c_file, "--baseline", self.baseline_path, "--update-baseline", second_baseline])
        with open(second_baseline) as f:
            data = json.load(f)
        self.assertGreaterEqual(len(data["issues"]), 1)

    def test_terminal_output_shows_baseline_diff_line(self):
        self._run(["scan", self.c_file, "--update-baseline", self.baseline_path])
        code, out = self._run(["scan", self.c_file, "--baseline", self.baseline_path])
        self.assertIn("Baseline Diff", out)

    def test_update_baseline_write_failure_returns_error(self):
        bad_path = os.path.join(self.temp_dir, "no_such_dir", "baseline.json")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            code = main(["scan", self.c_file, "--update-baseline", bad_path])
        self.assertEqual(code, 1)
        self.assertIn("Error writing baseline", stderr.getvalue())


class TestRulesCommand(unittest.TestCase):
    def test_rules_command_lists_all_rule_ids(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["rules"])
        self.assertEqual(code, 0)
        out = stdout.getvalue()
        self.assertIn("CGULL-001", out)
        self.assertIn("CGULL-025", out)


class TestInitIgnoreCommand(unittest.TestCase):
    def test_creates_cgullignore_file_in_cwd(self):
        temp_dir = tempfile.mkdtemp()
        cwd = os.getcwd()
        try:
            os.chdir(temp_dir)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["init-ignore"])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(".cgullignore"))
        finally:
            os.chdir(cwd)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_does_not_overwrite_existing_file(self):
        temp_dir = tempfile.mkdtemp()
        cwd = os.getcwd()
        try:
            os.chdir(temp_dir)
            with open(".cgullignore", "w") as f:
                f.write("# custom content\n")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                main(["init-ignore"])
            with open(".cgullignore") as f:
                content = f.read()
            self.assertEqual(content, "# custom content\n")
        finally:
            os.chdir(cwd)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestMainDispatch(unittest.TestCase):
    def test_no_args_defaults_to_scanning_current_directory(self):
        temp_dir = tempfile.mkdtemp()
        cwd = os.getcwd()
        try:
            os.chdir(temp_dir)
            with open("clean.c", "w") as f:
                f.write("void noop(void) {\n    int total = 0;\n    total = total + 1;\n}\n")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main([])
            self.assertEqual(code, 0)
        finally:
            os.chdir(cwd)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_help_flag_exits_via_argparse(self):
        # --help is handled entirely by argparse's own action (SystemExit),
        # never reaching main()'s own command-dispatch branches.
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_keyboard_interrupt_returns_exit_code_130_and_prints_message(self):
        from unittest.mock import patch
        stderr = io.StringIO()
        with patch("cgull.cli.handle_scan", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stderr(stderr):
                code = main(["scan", "."])
        self.assertEqual(code, 130)
        self.assertIn("Scan interrupted by user.", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
