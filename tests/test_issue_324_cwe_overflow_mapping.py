"""Regression coverage for issue #324 Juliet CWE credit."""

from benchmarks.run_juliet import CWE_RULE_MAP


def test_cwe_121_and_122_credit_existing_overflow_rules():
    expected = {"CGULL-001", "CGULL-007", "CGULL-044"}

    assert CWE_RULE_MAP["CWE-121"] == expected
    assert CWE_RULE_MAP["CWE-122"] == expected
