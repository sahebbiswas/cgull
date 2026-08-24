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


if __name__ == "__main__":
    unittest.main()
