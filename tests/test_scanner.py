"""
Unit tests for C-GULL Core Scanning Engine and Security Rules.
"""

import unittest
import os
import json
import tempfile
import shutil

from cgull.engine import CGullScanner
from cgull.models import Severity, AnalysisEngine
from cgull.ignore import CGullIgnoreFilter
from cgull.reporter import ReportGenerator
from cgull.rules import get_all_rules, get_rule_by_id


class TestCGullScannerRules(unittest.TestCase):

    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_banned_functions_detection(self):
        code = """
        #include <stdio.h>
        #include <string.h>

        void vulnerable(char *src) {
            char buffer[64];
            gets(buffer);
            strcpy(buffer, src);
            strcat(buffer, "extra");
            sprintf(buffer, "%s", src);
        }
        """
        result = self.scanner.scan_text(code, "test_banned.c")
        banned_issues = [i for i in result.issues if i.rule_id == "CGULL-001"]
        self.assertGreaterEqual(len(banned_issues), 3)
        func_names = [i.message for i in banned_issues]
        self.assertTrue(any("gets" in msg for msg in func_names))
        self.assertTrue(any("strcpy" in msg for msg in func_names))
        self.assertTrue(any("sprintf" in msg for msg in func_names))

    def test_format_string_vulnerability(self):
        code = """
        #include <stdio.h>
        void log_user(char *user_input) {
            printf(user_input); // Format string bug!
            printf("%s", user_input); // Safe
        }
        """
        result = self.scanner.scan_text(code, "test_fmt.c")
        fmt_issues = [i for i in result.issues if i.rule_id == "CGULL-002"]
        self.assertEqual(len(fmt_issues), 1)
        self.assertIn("user_input", fmt_issues[0].message)

    def test_unchecked_dynamic_allocation(self):
        code = """
        #include <stdlib.h>
        void allocate_bad() {
            char *buf = (char *)malloc(1024);
            buf[0] = 'X'; // No null check
        }

        void allocate_good() {
            char *buf = (char *)malloc(1024);
            if (buf == NULL) return;
            buf[0] = 'X';
        }
        """
        result = self.scanner.scan_text(code, "test_alloc.c")
        alloc_issues = [i for i in result.issues if i.rule_id == "CGULL-003"]
        self.assertEqual(len(alloc_issues), 1)
        self.assertIn("buf", alloc_issues[0].message)

    def test_crypto_timing_attack(self):
        code = """
        #include <string.h>
        int check_auth_token(const char *user_token, const char *expected_token) {
            if (memcmp(user_token, expected_token, 32) == 0) {
                return 1;
            }
            return 0;
        }
        """
        result = self.scanner.scan_text(code, "test_crypto.c")
        timing_issues = [i for i in result.issues if i.rule_id == "CGULL-005"]
        self.assertGreaterEqual(len(timing_issues), 1)
        self.assertIn("timing", timing_issues[0].message.lower())

    def test_generic_buffer_comparison_not_flagged_as_secret(self):
        code = """
        #include <string.h>
        #include <stdint.h>

        int process_packet(const uint8_t *buf, const uint8_t *expected, size_t len) {
            if (memcmp(buf, expected, len) == 0) {
                return 0;
            }
            return -1;
        }

        int validate_header(const char *data, size_t data_len) {
            if (strncmp(data, "HEAD", 4) == 0) {
                return 1;
            }
            return 0;
        }
        """
        result = self.scanner.scan_text(code, "test_generic_comp.c")
        timing_issues = [i for i in result.issues if i.rule_id == "CGULL-005"]
        self.assertEqual(len(timing_issues), 0)

    def test_generic_memset_buffer_not_flagged(self):
        code = """
        #include <string.h>

        int clear_buffer(void) {
            char buf[64];
            memset(buf, 0, sizeof(buf));
            return 0;
        }
        """
        result = self.scanner.scan_text(code, "test_generic_memset.c")
        wipe_issues = [i for i in result.issues if i.rule_id == "CGULL-008"]
        self.assertEqual(len(wipe_issues), 0)

    def test_variable_length_arrays_vla(self):
        code = """
        void process_packet(int len) {
            char vla_buffer[len]; // VLA stack risk
        }
        """
        result = self.scanner.scan_text(code, "test_vla.c")
        vla_issues = [i for i in result.issues if i.rule_id == "CGULL-010"]
        self.assertEqual(len(vla_issues), 1)
        self.assertIn("Variable Length Array", vla_issues[0].message)

    def test_unsafe_integer_conversion_atoi(self):
        code = """
        #include <stdlib.h>
        int parse_port(char *str) {
            return atoi(str);
        }
        """
        result = self.scanner.scan_text(code, "test_atoi.c")
        atoi_issues = [i for i in result.issues if i.rule_id == "CGULL-012"]
        self.assertEqual(len(atoi_issues), 1)
        self.assertIn("atoi", atoi_issues[0].message)

    def test_naked_control_flow(self):
        code = """
        void check(int err) {
            if (err)
                goto fail;
        }
        """
        result = self.scanner.scan_text(code, "test_naked.c")
        naked_issues = [i for i in result.issues if i.rule_id == "CGULL-013"]
        self.assertGreaterEqual(len(naked_issues), 1)

    def test_use_after_free(self):
        code = """
        #include <stdlib.h>
        #include <stdio.h>

        struct Session { int id; };

        void clean_session(struct Session *s) {
            free(s);
            printf("ID: %d\\n", s->id);
        }
        """
        result = self.scanner.scan_text(code, "test_uaf.c")
        uaf_issues = [i for i in result.issues if i.rule_id == "CGULL-022"]
        self.assertEqual(len(uaf_issues), 1)
        self.assertIn("Use-After-Free", uaf_issues[0].message)

    def test_json_reporting(self):
        code = "void test() { char *p = (char *)malloc(10); gets(p); }"
        result = self.scanner.scan_text(code, "sample.c")
        json_output = ReportGenerator.to_json(result)
        parsed = json.loads(json_output)
        self.assertIn("summary", parsed)
        self.assertIn("issues", parsed)
        self.assertIn("meta", parsed)
        self.assertEqual(parsed["meta"]["tool"], "C-GULL")
        self.assertGreaterEqual(parsed["summary"]["total_issues_count"], 1)

    def test_sarif_reporting(self):
        code = "void test() { char buf[32]; gets(buf); }"
        result = self.scanner.scan_text(code, "sample.c")
        sarif_json = ReportGenerator.to_sarif(result)
        parsed = json.loads(sarif_json)
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertIn("runs", parsed)
        self.assertEqual(parsed["runs"][0]["tool"]["driver"]["name"], "C-GULL")


class TestCGullIgnoreFilter(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.ignore_filter = CGullIgnoreFilter(base_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_default_ignores(self):
        git_dir = os.path.join(self.temp_dir, ".git", "config")
        build_dir = os.path.join(self.temp_dir, "build", "main.o")
        self.assertTrue(self.ignore_filter.should_ignore(git_dir))
        self.assertTrue(self.ignore_filter.should_ignore(build_dir))

    def test_custom_patterns_and_file_loading(self):
        custom_ignore = """
        # Ignore vendor
        vendor/
        test_temp_*.c
        !vendor/important.c
        """
        self.ignore_filter.load_from_text(custom_ignore)

        vendor_file = os.path.join(self.temp_dir, "vendor", "lib.c")
        temp_c_file = os.path.join(self.temp_dir, "test_temp_99.c")
        normal_file = os.path.join(self.temp_dir, "src", "main.c")

        self.assertTrue(self.ignore_filter.should_ignore(vendor_file))
        self.assertTrue(self.ignore_filter.should_ignore(temp_c_file))
        self.assertFalse(self.ignore_filter.should_ignore(normal_file))


class TestDirectoryScanning(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # Create folder structure
        os.makedirs(os.path.join(self.temp_dir, "src"))
        os.makedirs(os.path.join(self.temp_dir, "vendor"))

        with open(os.path.join(self.temp_dir, "src", "main.c"), "w") as f:
            f.write("void test() { char buf[32]; gets(buf); }")

        with open(os.path.join(self.temp_dir, "vendor", "bad.c"), "w") as f:
            f.write("void vendor_test() { char buf[32]; gets(buf); }")

        with open(os.path.join(self.temp_dir, ".cgullignore"), "w") as f:
            f.write("vendor/\n")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_recursive_scan_with_cgullignore(self):
        scanner = CGullScanner()
        result = scanner.scan_path(self.temp_dir)
        self.assertEqual(result.scanned_files_count, 1)
        self.assertTrue(any("main.c" in fs.file_path for fs in result.file_summaries))
        self.assertFalse(any("bad.c" in fs.file_path for fs in result.file_summaries))


class TestFalsePositiveRegressions(unittest.TestCase):
    """
    Regression tests for false positives / false negatives found while
    reviewing the analyzer: banned-function names appearing only in
    comments or string literals, `return x;`-style statements being
    mis-parsed as variable declarations, and multi-declarator lines.
    """

    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_banned_function_name_in_trailing_comment_not_flagged(self):
        code = """
        void f(int x) {
            int result = x + 1; // avoid using strcpy() here, it's banned
        }
        """
        result = self.scanner.scan_text(code, "test_comment_fp.c")
        banned_issues = [i for i in result.issues if i.rule_id == "CGULL-001"]
        self.assertEqual(len(banned_issues), 0)

    def test_banned_function_name_in_string_literal_not_flagged(self):
        code = """
        void f(void) {
            char *name = "use gets() carefully";
        }
        """
        result = self.scanner.scan_text(code, "test_string_fp.c")
        banned_issues = [i for i in result.issues if i.rule_id == "CGULL-001"]
        self.assertEqual(len(banned_issues), 0)

    def test_real_banned_call_still_detected_alongside_lookalike_string(self):
        # A real strcpy() call on one line and a string mentioning strcpy()
        # on another -- only the real call should be flagged.
        code = """
        #include <string.h>
        void f(char *dest, char *src) {
            char *msg = "don't use strcpy()";
            strcpy(dest, src);
        }
        """
        result = self.scanner.scan_text(code, "test_mixed.c")
        banned_issues = [i for i in result.issues if i.rule_id == "CGULL-001"]
        self.assertEqual(len(banned_issues), 1)
        self.assertEqual(banned_issues[0].line_number, 5)

    def test_return_statement_not_mistaken_for_declaration(self):
        # Regression test: the regex variable-declaration extractor used
        # to parse `return c;` as if it were declaring a variable `c`,
        # firing CGULL-023 (uninitialized memory use) on ordinary
        # control-flow statements that reference a name never actually
        # declared anywhere in the function.
        code = """
        int compute(int x, int y) {
            int total = x + y;
            return total;
        }
        """
        result = self.scanner.scan_text(code, "test_return_fp.c")
        uninit_issues = [i for i in result.issues if i.rule_id == "CGULL-023"]
        self.assertEqual(len(uninit_issues), 0)

    def test_multi_declarator_line_all_vars_tracked(self):
        # int a, b, c; -- the single-declarator regex cannot represent
        # this; pycparser (when available) should recover all three.
        code = """
        int compute(int x, int y) {
            int a, b, c;
            a = x;
            b = y;
            c = a + b;
            return c;
        }
        """
        from cgull.ast_analyzer import CASTParser
        ctx = CASTParser().parse(code)
        if not ctx.has_pycparser:
            self.skipTest("pycparser not installed in this environment")
        fn = ctx.functions[0]
        self.assertIn("a", fn.variables)
        self.assertIn("b", fn.variables)
        self.assertIn("c", fn.variables)


class TestSuppressionComments(unittest.TestCase):

    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_suppress_specific_rule_same_line(self):
        code = """
        #include <string.h>
        void f(char *dest, char *src) {
            strcpy(dest, src); // cgull-ignore: CGULL-001
        }
        """
        result = self.scanner.scan_text(code, "test_suppress.c")
        self.assertEqual(len([i for i in result.issues if i.rule_id == "CGULL-001"]), 0)

    def test_suppress_all_rules_same_line(self):
        code = """
        #include <string.h>
        void f(char *dest, char *src) {
            strcpy(dest, src); // cgull-ignore
        }
        """
        result = self.scanner.scan_text(code, "test_suppress_all.c")
        self.assertEqual(len(result.issues), 0)

    def test_suppress_next_line(self):
        code = """
        #include <string.h>
        void f(char *dest, char *src) {
            // cgull-ignore-next-line: CGULL-001
            strcpy(dest, src);
        }
        """
        result = self.scanner.scan_text(code, "test_suppress_next.c")
        self.assertEqual(len([i for i in result.issues if i.rule_id == "CGULL-001"]), 0)

    def test_unrelated_rule_not_suppressed(self):
        code = """
        #include <string.h>
        void f(char *dest, char *src) {
            strcpy(dest, src); // cgull-ignore: CGULL-099
        }
        """
        result = self.scanner.scan_text(code, "test_suppress_wrong_rule.c")
        self.assertEqual(len([i for i in result.issues if i.rule_id == "CGULL-001"]), 1)


class TestParallelScanning(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        for i in range(4):
            with open(os.path.join(self.temp_dir, f"f{i}.c"), "w") as f:
                f.write(f"void t{i}() {{ char buf[32]; gets(buf); }}")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_parallel_scan_matches_sequential_scan(self):
        seq = CGullScanner().scan_path(self.temp_dir, jobs=1)
        par = CGullScanner().scan_path(self.temp_dir, jobs=2)
        self.assertEqual(seq.scanned_files_count, par.scanned_files_count)
        self.assertEqual(
            sorted((i.file_path, i.rule_id, i.line_number) for i in seq.issues),
            sorted((i.file_path, i.rule_id, i.line_number) for i in par.issues),
        )


if __name__ == "__main__":
    unittest.main()
