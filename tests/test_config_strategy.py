"""
Unit tests and strategy-comparison regression test for config-space expansion strategies.
"""

import os
import sys
import tempfile
import unittest

from cgull import CGullScanner, ConfigProfile, AnalysisEngine
from cgull.ast_analyzer import generate_config_profiles
from cgull.cli import main
from cgull.rules.banned_functions import BannedFunctionsRule


class TestConfigStrategyGeneration(unittest.TestCase):

    def test_baseline_strategy(self):
        flags = {"FLAG_A", "FLAG_B", "FLAG_C"}
        profiles = generate_config_profiles(flags, strategy="baseline")
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0], ConfigProfile("baseline", {}))

    def test_one_at_a_time_strategy(self):
        flags = {"FLAG_A", "FLAG_B"}
        profiles = generate_config_profiles(flags, strategy="one-at-a-time")
        self.assertEqual(len(profiles), 3)  # 1 baseline + 2 single-flip variants
        self.assertEqual(profiles[0].name, "baseline")
        self.assertEqual(profiles[1].flags, {"FLAG_A": None})
        self.assertEqual(profiles[2].flags, {"FLAG_B": None})

    def test_pairwise_strategy_covers_all_flag_pairs(self):
        flags = ["FLAG_A", "FLAG_B", "FLAG_C"]
        profiles = generate_config_profiles(flags, strategy="pairwise")

        # Verify pairwise covers all 4 combinations for every pair of flags
        for i in range(len(flags)):
            for j in range(i + 1, len(flags)):
                f1, f2 = flags[i], flags[j]
                seen_pairs = set()
                for p in profiles:
                    val1 = 1 if f1 in p.flags else 0
                    val2 = 1 if f2 in p.flags else 0
                    seen_pairs.add((val1, val2))
                self.assertEqual(seen_pairs, {(0, 0), (0, 1), (1, 0), (1, 1)}, f"Pair ({f1}, {f2}) not fully covered")

    def test_exhaustive_strategy_below_threshold(self):
        flags = {"FLAG_A", "FLAG_B", "FLAG_C"}
        profiles = generate_config_profiles(flags, strategy="exhaustive", exhaustive_threshold=10)
        self.assertEqual(len(profiles), 2 ** 3)  # 8 profiles for 3 flags

    def test_exhaustive_strategy_exceeding_threshold_raises_value_error(self):
        flags = {f"FLAG_{i}" for i in range(12)}
        with self.assertRaises(ValueError) as cm:
            generate_config_profiles(flags, strategy="exhaustive", exhaustive_threshold=10)

        err_msg = str(cm.exception)
        self.assertIn("12", err_msg)
        self.assertIn("10", err_msg)
        self.assertIn("pairwise", err_msg)

    def test_invalid_strategy_raises_value_error(self):
        with self.assertRaises(ValueError):
            generate_config_profiles({"FLAG_A"}, strategy="invalid_strat")


class TestConfigStrategyRegressionFixture(unittest.TestCase):
    """
    Clean strategy-comparison regression test:
    A fixture with a bug only reachable when two specific flags are BOTH set.
    Undetectable by baseline and one-at-a-time by construction.
    Caught under pairwise and exhaustive strategies.
    """

    def test_two_flag_interaction_vulnerability_strategy_comparison(self):
        source_code = (
            "#include <string.h>\n"
            "#include <stdio.h>\n"
            "\n"
            "void process_data(char *dst, const char *src) {\n"
            "    (void)dst;\n"
            "    (void)src;\n"
            "#if defined(ENABLE_SECURITY) && defined(ALLOW_LEGACY_COPY)\n"
            "    strcpy(dst, src);\n"
            "#endif\n"
            "}\n"
        )

        scanner = CGullScanner(rules=[BannedFunctionsRule()], engine_mode=AnalysisEngine.HYBRID)

        # 1. Baseline strategy: 0 findings
        res_baseline = scanner.scan_text(source_code, config_strategy="baseline")
        self.assertEqual(len(res_baseline.issues), 0)

        # 2. One-at-a-time strategy: 0 findings (neither profile has BOTH flags defined)
        res_one_at_a_time = scanner.scan_text(source_code, config_strategy="one-at-a-time")
        self.assertEqual(len(res_one_at_a_time.issues), 0)

        # 3. Pairwise strategy: 1 finding (caught under combination where both flags are defined)
        res_pairwise = scanner.scan_text(source_code, config_strategy="pairwise")
        self.assertEqual(len(res_pairwise.issues), 1)
        self.assertIn("strcpy", res_pairwise.issues[0].message)
        self.assertEqual(res_pairwise.issues[0].reachable_under, ["+ALLOW_LEGACY_COPY, ENABLE_SECURITY"])

        # 4. Exhaustive strategy: 1 finding (caught under combination where both flags are defined)
        res_exhaustive = scanner.scan_text(source_code, config_strategy="exhaustive", exhaustive_threshold=10)
        self.assertEqual(len(res_exhaustive.issues), 1)
        self.assertIn("strcpy", res_exhaustive.issues[0].message)
        self.assertEqual(res_exhaustive.issues[0].reachable_under, ["+ALLOW_LEGACY_COPY, ENABLE_SECURITY"])


class TestConfigStrategyCLI(unittest.TestCase):

    def test_cli_pairwise_strategy(self):
        source_code = (
            "#include <string.h>\n"
            "void f(char *d, char *s) {\n"
            "    (void)d;\n"
            "    (void)s;\n"
            "#if defined(FLAG_A) && defined(FLAG_B)\n"
            "    strcpy(d, s);\n"
            "#endif\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test.c")
            report_path = os.path.join(tmpdir, "report.json")
            with open(file_path, "w") as f:
                f.write(source_code)

            # Test pairwise via CLI
            exit_code = main(["scan", tmpdir, "--config-strategy", "pairwise", "-o", report_path, "-f", "json"])
            self.assertEqual(exit_code, 0)

            import json
            with open(report_path, "r") as f:
                report = json.load(f)

            self.assertEqual(len(report["issues"]), 1)
            self.assertIn("strcpy", report["issues"][0]["message"])

    def test_cli_exhaustive_threshold_exceeded_error(self):
        source_code = "\n".join([f"#ifdef FLAG_{i}\nint x_{i};\n#endif" for i in range(12)])
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test.c")
            with open(file_path, "w") as f:
                f.write(source_code)

            exit_code = main(["scan", tmpdir, "--config-strategy", "exhaustive", "--exhaustive-threshold", "10"])
            self.assertEqual(exit_code, 1)

    def test_ignored_directory_flags_do_not_inflate_exhaustive_threshold(self):
        """
        Tests that flags in ignored directories do not inflate discovered flag count
        or trigger threshold validation failure under exhaustive strategy.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, "src")
            vendor_dir = os.path.join(tmpdir, "vendor")
            os.makedirs(src_dir)
            os.makedirs(vendor_dir)

            with open(os.path.join(src_dir, "main.c"), "w") as f:
                f.write("#ifdef FLAG_A\nint a;\n#endif\n#ifdef FLAG_B\nint b;\n#endif\n")

            vendor_content = "\n".join([f"#ifdef VENDOR_FLAG_{i}\nint v_{i};\n#endif" for i in range(12)])
            with open(os.path.join(vendor_dir, "lib.c"), "w") as f:
                f.write(vendor_content)

            report_path = os.path.join(tmpdir, "report.json")
            exit_code = main([
                "scan", tmpdir,
                "--ignore-pattern", "vendor/",
                "--config-strategy", "exhaustive",
                "--exhaustive-threshold", "10",
                "-o", report_path,
                "-f", "json",
            ])
            self.assertEqual(exit_code, 0)

            import json
            with open(report_path, "r") as f:
                report = json.load(f)
            self.assertEqual(report["summary"]["scanned_files_count"], 1)

    def test_uppercase_file_extension_flag_discovery_and_pairwise_expansion(self):
        """
        Tests that files with uppercase extensions like TEST.C participate in flag discovery
        and pairwise strategy expansion.
        """
        source_code = (
            "#include <string.h>\n"
            "void g(char *d, char *s) {\n"
            "    (void)d; (void)s;\n"
            "#if defined(UPPER_A) && defined(UPPER_B)\n"
            "    strcpy(d, s);\n"
            "#endif\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "TEST.C")
            report_path = os.path.join(tmpdir, "report.json")
            with open(file_path, "w") as f:
                f.write(source_code)

            exit_code = main(["scan", tmpdir, "--config-strategy", "pairwise", "-o", report_path, "-f", "json"])
            self.assertEqual(exit_code, 0)

            import json
            with open(report_path, "r") as f:
                report = json.load(f)

            strcpy_iss = next((i for i in report["issues"] if "strcpy" in i["message"]), None)
            self.assertIsNotNone(strcpy_iss)
            self.assertEqual(strcpy_iss["reachable_under"], ["+UPPER_A, UPPER_B"])

    def test_scan_config_strategy_and_threshold_propagation(self):
        """
        Tests that ScanConfig.config_strategy and exhaustive_threshold are preserved through
        _get_active_config() and honored during scan_text().
        """
        from cgull.models import ScanConfig
        source_code = "\n".join([f"#ifdef COND_FLAG_{i}\nint x_{i};\n#endif" for i in range(8)])

        cfg = ScanConfig.create(
            rules=[BannedFunctionsRule()],
            config_strategy="exhaustive",
            exhaustive_threshold=5,
        )
        scanner = CGullScanner(config=cfg)

        with self.assertRaises(ValueError) as cm:
            scanner.scan_text(source_code)

        err_msg = str(cm.exception)
        self.assertIn("8", err_msg)
        self.assertIn("5", err_msg)

    def test_unreadable_file_flag_collection_logs_warning_without_crashing(self):
        """
        Tests that unreadable files emit a warning during flag collection without crashing the scan.
        """
        from cgull.engine import _collect_files_presence_flags
        import io
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmpdir:
            good_file = os.path.join(tmpdir, "good.c")
            bad_file = os.path.join(tmpdir, "bad.c")

            with open(good_file, "w") as f:
                f.write("#ifdef GOOD_FLAG\nint g;\n#endif\n")
            with open(bad_file, "w") as f:
                f.write("#ifdef BAD_FLAG\nint b;\n#endif\n")

            real_open = open

            def mock_open(file, *args, **kwargs):
                if os.path.abspath(str(file)) == os.path.abspath(bad_file):
                    raise PermissionError(f"Permission denied: {bad_file}")
                return real_open(file, *args, **kwargs)

            stderr_buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = stderr_buf
            try:
                with patch("builtins.open", side_effect=mock_open):
                    flags = _collect_files_presence_flags([good_file, bad_file], quiet=False)
            finally:
                sys.stderr = old_stderr

            self.assertIn("GOOD_FLAG", flags)
            self.assertNotIn("BAD_FLAG", flags)
            self.assertIn("Flag collection skipped", stderr_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
