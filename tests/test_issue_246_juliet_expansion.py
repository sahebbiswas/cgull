"""Regression coverage for issue #246 Juliet CWE expansion."""

import json
import os

from benchmarks.run_juliet import CATEGORIES, CWE_RULE_MAP, extract_function_line_ranges, run_juliet_benchmark


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MANIFEST_PATH = os.path.join(REPO_ROOT, "benchmarks", "juliet", "manifest_expanded.json")


def test_expanded_juliet_manifest_structure():
    with open(MANIFEST_PATH, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    assert CWE_RULE_MAP["CWE-415"] == {"CGULL-027"}
    assert CWE_RULE_MAP["CWE-401"] == {"CGULL-036"}
    assert CWE_RULE_MAP["CWE-562"] == {"CGULL-038"}

    test_cases = manifest["test_cases"]
    assert len(test_cases) == 6
    assert {tc["cwe"] for tc in test_cases} == {"CWE-415", "CWE-401", "CWE-562"}
    assert {tc["category"] for tc in test_cases} == {"baseline", "if/else"}

    for tc in test_cases:
        assert tc["category"] in CATEGORIES
        assert tc["ci_subset"] is True
        source_path = os.path.join(os.path.dirname(MANIFEST_PATH), tc["file"])
        assert os.path.exists(source_path)
        ranges = extract_function_line_ranges(source_path)
        for oracle in tc["oracle"]:
            assert oracle["function"] in ranges
            assert set(oracle["expected_rules"]) <= CWE_RULE_MAP[tc["cwe"]]


def test_expanded_juliet_quality_gate():
    results = run_juliet_benchmark(MANIFEST_PATH, ci_only=True)

    assert results["total_test_cases_evaluated"] == 6
    assert results["failed_test_cases_count"] == 0
    assert set(results["by_rule"]) == {"CGULL-027", "CGULL-036", "CGULL-038"}
    assert results["overall"]["f1"] >= 0.90
    for rule_id in ("CGULL-027", "CGULL-036", "CGULL-038"):
        metrics = results["by_rule"][rule_id]
        assert metrics["tp"] > 0
        assert metrics["tn"] > 0
