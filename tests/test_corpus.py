"""
Integration test module for C-GULL Security Rule Behavioral Corpus.
Invokes the standalone corpus runner to verify behavioral security rules.
"""

import os
import unittest
from .run_corpus import run_corpus_scan, REPO_ROOT


class TestSecurityRuleBehavioralCorpus(unittest.TestCase):
    """
    Executes the security rule behavioral corpus across all rule suites in tests/rules/.
    Ensures every target rule correctly detects true positives, true negatives,
    false-positive regressions, and false-negative regressions.
    """

    def setUp(self):
        self.rules_dir = os.path.join(REPO_ROOT, "tests", "rules")

    def test_full_corpus_suite(self):
        success, report = run_corpus_scan(self.rules_dir, verbose=False)
        self.assertTrue(success, f"Behavioral Corpus Verification Failed:\n{report}")

    def test_rule_cgull_003_unchecked_allocations(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-003", verbose=False)
        self.assertTrue(success, f"CGULL-003 Corpus Failed:\n{report}")

    def test_rule_cgull_004_pointer_param_validation(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-004", verbose=False)
        self.assertTrue(success, f"CGULL-004 Corpus Failed:\n{report}")

    def test_rule_cgull_006_integer_overflow(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-006", verbose=False)
        self.assertTrue(success, f"CGULL-006 Corpus Failed:\n{report}")

    def test_rule_cgull_007_array_out_of_bounds(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-007", verbose=False)
        self.assertTrue(success, f"CGULL-007 Corpus Failed:\n{report}")

    def test_rule_cgull_021_uninitialized_pointers(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-021", verbose=False)
        self.assertTrue(success, f"CGULL-021 Corpus Failed:\n{report}")

    def test_rule_cgull_022_use_after_free(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-022", verbose=False)
        self.assertTrue(success, f"CGULL-022 Corpus Failed:\n{report}")

    def test_rule_cgull_023_uninitialized_memory_use(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-023", verbose=False)
        self.assertTrue(success, f"CGULL-023 Corpus Failed:\n{report}")

    def test_rule_cgull_026_snprintf_return_value(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-026", verbose=False)
        self.assertTrue(success, f"CGULL-026 Corpus Failed:\n{report}")

    def test_rule_cgull_027_double_free(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-027", verbose=False)
        self.assertTrue(success, f"CGULL-027 Corpus Failed:\n{report}")

    def test_rule_cgull_028_insecure_prng(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-028", verbose=False)
        self.assertTrue(success, f"CGULL-028 Corpus Failed:\n{report}")


if __name__ == "__main__":
    unittest.main()
