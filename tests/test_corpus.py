"""
Integration test module for C-GULL Security Rule Behavioral Corpus.
Invokes the standalone corpus runner to verify behavioral security rules.
"""

import os
import unittest

if __package__:
    from .run_corpus import run_corpus_scan, REPO_ROOT
else:  # unittest discovery imports test modules as top-level modules.
    from run_corpus import run_corpus_scan, REPO_ROOT


class TestSecurityRuleBehavioralCorpus(unittest.TestCase):
    """
    Executes the security rule behavioral corpus across all rule suites in tests/rules/.
    Ensures every target rule correctly detects true positives, true negatives,
    false-positive regressions, and false-negative regressions.
    """

    def setUp(self):
        self.rules_dir = os.path.join(REPO_ROOT, "tests", "rules")

    def test_rule_cgull_037_strncpy(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-037", verbose=False)
        self.assertTrue(success, f"CGULL-037 Corpus Failed:\n{report}")

    def test_full_corpus_suite(self):
        success, report = run_corpus_scan(self.rules_dir, verbose=False, min_behavioral_coverage=40.0)
        self.assertTrue(success, f"Behavioral Corpus Verification Failed:\n{report}")

    def test_rule_cgull_002_format_string(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-002", verbose=False)
        self.assertTrue(success, f"CGULL-002 Corpus Failed:\n{report}")

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

    def test_rule_cgull_029_sizeof_pointer(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-029", verbose=False)
        self.assertTrue(success, f"CGULL-029 Corpus Failed:\n{report}")

    def test_rule_cgull_030_command_injection(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-030", verbose=False)
        self.assertTrue(success, f"CGULL-030 Corpus Failed:\n{report}")

    def test_rule_cgull_031_weak_crypto_primitives(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-031", verbose=False)
        self.assertTrue(success, f"CGULL-031 Corpus Failed:\n{report}")

    def test_rule_cgull_033_signed_unsigned_comparison(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-033", verbose=False)
        self.assertTrue(success, f"CGULL-033 Corpus Failed:\n{report}")

    def test_rule_cgull_035_toctou_file_access(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-035", verbose=False)
        self.assertTrue(success, f"CGULL-035 Corpus Failed:\n{report}")

    def test_rule_cgull_036_memory_leak(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-036", verbose=False)
        self.assertTrue(success, f"CGULL-036 Corpus Failed:\n{report}")

    def test_rule_cgull_038_return_stack_variable(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-038", verbose=False)
        self.assertTrue(success, f"CGULL-038 Corpus Failed:\n{report}")

    def test_rule_cgull_045_missing_inclusion_guard(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-045", verbose=False)
        self.assertTrue(success, f"CGULL-045 Corpus Failed:\n{report}")

    def test_rule_cgull_032(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-032", verbose=False)
        self.assertTrue(success, f"CGULL-032 Corpus Failed:\n{report}")

    def test_rule_cgull_034(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-034", verbose=False)
        self.assertTrue(success, f"CGULL-034 Corpus Failed:\n{report}")

    def test_rule_cgull_039(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-039", verbose=False)
        self.assertTrue(success, f"CGULL-039 Corpus Failed:\n{report}")

    def test_rule_cgull_040(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-040", verbose=False)
        self.assertTrue(success, f"CGULL-040 Corpus Failed:\n{report}")

    def test_rule_cgull_041(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-041", verbose=False)
        self.assertTrue(success, f"CGULL-041 Corpus Failed:\n{report}")

    def test_rule_cgull_042(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-042", verbose=False)
        self.assertTrue(success, f"CGULL-042 Corpus Failed:\n{report}")

    def test_rule_cgull_043(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-043", verbose=False)
        self.assertTrue(success, f"CGULL-043 Corpus Failed:\n{report}")

    def test_rule_cgull_046(self):
        success, report = run_corpus_scan(self.rules_dir, target_rule_id="CGULL-046", verbose=False)
        self.assertTrue(success, f"CGULL-046 Corpus Failed:\n{report}")


if __name__ == "__main__":
    unittest.main()
