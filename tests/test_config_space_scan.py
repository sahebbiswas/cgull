"""
Tests for per-config scan execution and condition-tagged findings (reachable_under).
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from cgull import CGullScanner, ConfigProfile, AnalysisEngine
from cgull.ast_analyzer import CASTParser, resolve_preprocessor_conditionals
from cgull.rules.banned_functions import BannedFunctionsRule


class TestConfigSpaceScan(unittest.TestCase):
    def test_legacy_auth_regression_fixture(self):
        """
        Concrete regression test fixture:
        A file with a vulnerability (banned strcpy) inside #ifdef LEGACY_AUTH and
        an unconditional vulnerability (gets) outside #ifdef LEGACY_AUTH.

        - Single-pass baseline scan (without LEGACY_AUTH defined):
          Produces 0 strcpy findings (only gets).
        - Config-space scan with profiles [baseline, LEGACY_AUTH]:
          Produces 2 findings under both Tier 1 (pcpp) and Tier 2 (directive-stripped fallback):
          1. strcpy with reachable_under: ["+LEGACY_AUTH"]
          2. gets with reachable_under: ["unconditional"]
        """
        source_code = (
            "#include <string.h>\n"
            "#include <stdio.h>\n"
            "\n"
            "void auth_user(char *dst, const char *src) {\n"
            "    (void)src;\n"
            "#ifdef LEGACY_AUTH\n"
            "    strcpy(dst, src);\n"
            "#endif\n"
            "    gets(dst);\n"
            "}\n"
        )

        scanner = CGullScanner(rules=[BannedFunctionsRule()], engine_mode=AnalysisEngine.HYBRID)

        # Single-pass scan without LEGACY_AUTH defined
        baseline_res = scanner.scan_text(source_code)
        self.assertEqual(len(baseline_res.issues), 1)
        self.assertIn("gets", baseline_res.issues[0].message)

        # Config-space scan with profiles
        profiles = [
            ConfigProfile("baseline", {}),
            ConfigProfile("LEGACY_AUTH", {"LEGACY_AUTH": None}),
        ]

        # Tier 1 execution (pcpp enabled by default if installed)
        config_res_tier1 = scanner.scan_text_profiles(source_code, profiles=profiles)
        self.assertEqual(len(config_res_tier1.issues), 2)

        strcpy_issue1 = next(i for i in config_res_tier1.issues if "strcpy" in i.message)
        gets_issue1 = next(i for i in config_res_tier1.issues if "gets" in i.message)

        self.assertEqual(strcpy_issue1.reachable_under, ["+LEGACY_AUTH"])
        self.assertEqual(gets_issue1.reachable_under, ["unconditional"])

        # Tier 2 execution (simulate pcpp unavailable)
        with patch.object(CASTParser, "_try_pcpp_preprocess", return_value=None):
            config_res_tier2 = scanner.scan_text_profiles(source_code, profiles=profiles)
            self.assertEqual(len(config_res_tier2.issues), 2)

            strcpy_issue2 = next(i for i in config_res_tier2.issues if "strcpy" in i.message)
            gets_issue2 = next(i for i in config_res_tier2.issues if "gets" in i.message)

            self.assertEqual(strcpy_issue2.reachable_under, ["+LEGACY_AUTH"])
            self.assertEqual(gets_issue2.reachable_under, ["unconditional"])

    def test_multiple_config_profiles_tagging(self):
        source_code = (
            "#include <stdio.h>\n"
            "#include <string.h>\n"
            "\n"
            "void process_data(char *buf) {\n"
            "#if defined(FEATURE_A) && defined(FEATURE_B)\n"
            "    gets(buf);\n"
            "#elif defined(FEATURE_A)\n"
            "    strcpy(buf, \"input\");\n"
            "#endif\n"
            "}\n"
        )

        profiles = [
            ConfigProfile("baseline", {}),
            ConfigProfile("FEATURE_A", {"FEATURE_A": None}),
            ConfigProfile("BOTH", {"FEATURE_A": None, "FEATURE_B": None}),
        ]

        scanner = CGullScanner(rules=[BannedFunctionsRule()])
        res = scanner.scan_text_profiles(source_code, profiles=profiles)

        # gets should be reachable under BOTH
        # strcpy should be reachable under FEATURE_A
        gets_issue = next((i for i in res.issues if "gets" in i.message), None)
        strcpy_issue = next((i for i in res.issues if "strcpy" in i.message), None)

        self.assertIsNotNone(gets_issue)
        self.assertEqual(gets_issue.reachable_under, ["+BOTH"])

        self.assertIsNotNone(strcpy_issue)
        self.assertEqual(strcpy_issue.reachable_under, ["+FEATURE_A"])

    def test_multi_file_config_scan_parallel(self):
        file_content_1 = (
            "#include <string.h>\n"
            "void f1(char *d, char *s) {\n"
            "    (void)d; (void)s;\n"
            "#ifdef OPT_X\n"
            "    strcpy(d, s);\n"
            "#endif\n"
            "}\n"
        )
        file_content_2 = (
            "#include <stdio.h>\n"
            "void f2(char *d) {\n"
            "    (void)d;\n"
            "    gets(d);\n"
            "}\n"
        )

        profiles = [
            ConfigProfile("baseline", {}),
            ConfigProfile("OPT_X", {"OPT_X": None}),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = os.path.join(tmpdir, "f1.c")
            file2 = os.path.join(tmpdir, "f2.c")

            with open(file1, "w") as f:
                f.write(file_content_1)
            with open(file2, "w") as f:
                f.write(file_content_2)

            scanner = CGullScanner(rules=[BannedFunctionsRule()])

            # Sequential multi-config scan
            res_seq = scanner.scan_profiles(tmpdir, profiles=profiles, jobs=1)
            self.assertEqual(res_seq.total_issues_count, 2)

            strcpy_iss = next(i for i in res_seq.issues if "strcpy" in i.message)
            gets_iss = next(i for i in res_seq.issues if "gets" in i.message)

            self.assertEqual(strcpy_iss.reachable_under, ["+OPT_X"])
            self.assertEqual(gets_iss.reachable_under, ["unconditional"])

            # Parallel multi-config scan (jobs=2)
            res_par = scanner.scan_profiles(tmpdir, profiles=profiles, jobs=2)
            self.assertEqual(res_par.total_issues_count, 2)

            strcpy_par = next(i for i in res_par.issues if "strcpy" in i.message)
            gets_par = next(i for i in res_par.issues if "gets" in i.message)

            self.assertEqual(strcpy_par.reachable_under, ["+OPT_X"])
            self.assertEqual(gets_par.reachable_under, ["unconditional"])

    def test_function_like_macro_conditional_resolution(self):
        """Tests that function-like macros #define LOG_MSG(x) ... register in resolver."""
        source_code = (
            "#define LOG_MSG(x) (void)(x)\n"
            "#ifdef LOG_MSG\n"
            "    gets(buf);\n"
            "#endif\n"
        )
        resolved = resolve_preprocessor_conditionals(source_code)
        self.assertIn("gets(buf);", resolved)

    def test_tier2_pycparser_directive_stripping(self):
        """Tests that Tier 2 strips preprocessor directives before passing to pycparser."""
        source_code = (
            "#define BUFFER_SIZE 64\n"
            "#include <stdio.h>\n"
            "void test_fn(void) {\n"
            "    char buf[64];\n"
            "}\n"
        )
        parser = CASTParser()
        with patch.object(parser, "_try_pcpp_preprocess", return_value=None):
            ast_ctx = parser.parse(source_code)
            self.assertTrue(ast_ctx.has_pycparser)
            self.assertEqual(len(ast_ctx.functions), 1)

    def test_duplicate_config_profiles_deduplication(self):
        """Duplicate ConfigProfiles in requested profiles list must be deduplicated so unconditional reachability is preserved."""
        source_code = (
            "#include <stdio.h>\n"
            "void f(char *b) { (void)b; gets(b); }\n"
        )
        profiles = [
            ConfigProfile("debug", {"DEBUG": None}),
            ConfigProfile("debug", {"DEBUG": None}),
        ]
        scanner = CGullScanner(rules=[BannedFunctionsRule()])
        res = scanner.scan_text_profiles(source_code, profiles=profiles)
        self.assertEqual(len(res.issues), 1)
        self.assertEqual(res.issues[0].reachable_under, ["unconditional"])

    def test_unnamed_config_profile_labeling(self):
        """Unnamed profile ConfigProfile('') should render as '+default'."""
        source_code = (
            "#include <stdio.h>\n"
            "#ifdef FLAG\n"
            "void f(char *b) { (void)b; gets(b); }\n"
            "#endif\n"
        )
        profiles = [
            ConfigProfile(""),
            ConfigProfile("FLAG", {"FLAG": None}),
        ]
        scanner = CGullScanner(rules=[BannedFunctionsRule()])
        res = scanner.scan_text_profiles(source_code, profiles=profiles)
        self.assertEqual(len(res.issues), 1)
        self.assertEqual(res.issues[0].reachable_under, ["+FLAG"])

    def test_tier1_and_tier2_if_eval_parity_for_presence_and_non_numeric(self):
        """
        Tests that #if evaluation parity between Tier 1 and Tier 2 holds for:
        1. Presence macros defined as None or in sequences (evaluating as truthy integer 1 in #if).
        2. Non-numeric string macros (evaluating as truthy integer 1 in #if).
        """
        source_code = (
            "#include <stdio.h>\n"
            "#include <string.h>\n"
            "void test_fn(char *buf, const char *src) {\n"
            "    (void)src;\n"
            "#if PRESENCE_FLAG\n"
            "    gets(buf);\n"
            "#endif\n"
            "#if NON_NUMERIC_MODE\n"
            "    strcpy(buf, src);\n"
            "#endif\n"
            "}\n"
        )

        profiles = [
            ConfigProfile("baseline", {}),
            ConfigProfile("CONFIG_PRESENCE", {"PRESENCE_FLAG": None}),
            ConfigProfile("CONFIG_NON_NUMERIC", {"NON_NUMERIC_MODE": "DEBUG"}),
        ]

        scanner = CGullScanner(rules=[BannedFunctionsRule()])

        # Tier 1
        res1 = scanner.scan_text_profiles(source_code, profiles=profiles)
        gets1 = next((i for i in res1.issues if "gets" in i.message), None)
        strcpy1 = next((i for i in res1.issues if "strcpy" in i.message), None)
        self.assertIsNotNone(gets1)
        self.assertEqual(gets1.reachable_under, ["+CONFIG_PRESENCE"])
        self.assertIsNotNone(strcpy1)
        self.assertEqual(strcpy1.reachable_under, ["+CONFIG_NON_NUMERIC"])

        # Tier 2
        with patch.object(CASTParser, "_try_pcpp_preprocess", return_value=None):
            res2 = scanner.scan_text_profiles(source_code, profiles=profiles)
            gets2 = next((i for i in res2.issues if "gets" in i.message), None)
            strcpy2 = next((i for i in res2.issues if "strcpy" in i.message), None)
            self.assertIsNotNone(gets2)
            self.assertEqual(gets2.reachable_under, ["+CONFIG_PRESENCE"])
            self.assertIsNotNone(strcpy2)
            self.assertEqual(strcpy2.reachable_under, ["+CONFIG_NON_NUMERIC"])


if __name__ == "__main__":
    unittest.main()
