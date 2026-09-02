"""
Unit tests for NIST Juliet Security Benchmark suite and runner.
"""

import os
import sys
import json
import re
import pytest
from unittest.mock import patch, MagicMock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmarks.run_juliet import (
    run_juliet_benchmark,
    compute_metrics,
    extract_function_line_ranges,
    format_text_report,
    format_markdown_report,
    is_issue_from_source,
    main,
    CATEGORIES,
    CWE_RULE_MAP,
    CWES,
)
from cgull.models import ScanResult, ScanError, Issue, Severity

MANIFEST_PATH = os.path.join(REPO_ROOT, "benchmarks", "juliet", "manifest.json")


def test_manifest_structure_and_validity():
    assert os.path.exists(MANIFEST_PATH), "Manifest file does not exist"
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert "test_cases" in manifest
    test_cases = manifest["test_cases"]
    assert len(test_cases) == 41
    rule_contracts = manifest["rule_contracts"]

    assert CWE_RULE_MAP["CWE-134"] == {"CGULL-002"}
    assert CWE_RULE_MAP["CWE-190"] == {"CGULL-006"}
    assert CWE_RULE_MAP["CWE-121"] == {"CGULL-007"}
    assert CWE_RULE_MAP["CWE-122"] == {"CGULL-007"}
    assert CWE_RULE_MAP["CWE-369"] == {"CGULL-034"}

    seen_ids = set()
    for tc in test_cases:
        assert "id" in tc
        assert tc["id"] not in seen_ids, f"Duplicate test ID found: {tc['id']}"
        seen_ids.add(tc["id"])

        assert tc["cwe"] in CWES
        assert tc["category"] in CATEGORIES
        assert "file" in tc
        abs_file = os.path.join(os.path.dirname(MANIFEST_PATH), tc["file"])
        assert os.path.exists(abs_file), f"Test case source file missing: {abs_file}"

        assert "oracle" in tc
        assert len(tc["oracle"]) >= 2
        abs_file = os.path.join(os.path.dirname(MANIFEST_PATH), tc["file"])
        function_ranges = extract_function_line_ranges(abs_file)
        with open(abs_file, "r", encoding="utf-8") as source_file:
            source_lines = source_file.readlines()

        for o in tc["oracle"]:
            assert "function" in o
            assert "vulnerable" in o
            assert isinstance(o["vulnerable"], bool)
            assert "expected_cwe" in o
            assert o["expected_cwe"] == tc["cwe"]
            assert "expected_rules" in o
            assert o["expected_rules"], "Every oracle needs at least one applicable rule for per-rule metrics"
            assert len(o["expected_rules"]) == len(set(o["expected_rules"]))
            assert set(o["expected_rules"]) <= CWE_RULE_MAP[o["expected_cwe"]]
            if tc["category"] == "interprocedural cases":
                assert "helper_functions" in o
                assert len(o["helper_functions"]) > 0

            oracle_functions = [o["function"], *o.get("helper_functions", [])]
            oracle_source = "".join(
                line
                for function in oracle_functions
                for start, end in [function_ranges[function]]
                for line in source_lines[start - 1:end]
            )
            for rule_id in o["expected_rules"]:
                contract = rule_contracts[rule_id]
                assert contract["rationale"].strip()
                assert re.search(contract["source_pattern"], oracle_source), (
                    f"{tc['id']}:{o['function']} has no source pattern for {rule_id}"
                )

    expected_rules = {
        rule_id
        for tc in test_cases
        for oracle in tc["oracle"]
        for rule_id in oracle["expected_rules"]
    }
    assert set(rule_contracts) == expected_rules

    cwe476_oracles = [
        oracle
        for tc in test_cases if tc["cwe"] == "CWE-476"
        for oracle in tc["oracle"]
    ]
    assert all(oracle["expected_rules"] == ["CGULL-004"] for oracle in cwe476_oracles)

    cwe457_cases = [tc for tc in test_cases if tc["cwe"] == "CWE-457"]
    for tc in cwe457_cases:
        expected = ["CGULL-021", "CGULL-023"] if tc["category"] == "interprocedural cases" else ["CGULL-021"]
        assert all(oracle["expected_rules"] == expected for oracle in tc["oracle"])


def test_compute_metrics():
    m = compute_metrics(tp=10, fp=2, tn=20, fn=3)
    assert m["tp"] == 10
    assert m["fp"] == 2
    assert m["tn"] == 20
    assert m["fn"] == 3
    assert m["precision"] == round(10 / 12, 4)
    assert m["recall"] == round(10 / 13, 4)
    assert m["f1"] == round(2 * m["precision"] * m["recall"] / (m["precision"] + m["recall"]), 4)

    # Edge cases (zero totals)
    m_zero = compute_metrics(0, 0, 0, 0)
    assert m_zero["precision"] == 0.0
    assert m_zero["recall"] == 0.0
    assert m_zero["f1"] == 0.0


def test_is_issue_from_source():
    manifest_dir = os.path.join(REPO_ROOT, "benchmarks", "juliet")
    abs_src = os.path.join(manifest_dir, "testcases", "CWE476_NULL_Pointer_Dereference__01_baseline.c")

    # Match exact absolute path
    assert is_issue_from_source(abs_src, abs_src, manifest_dir) is True

    # Match relative path from manifest
    rel_src = "testcases/CWE476_NULL_Pointer_Dereference__01_baseline.c"
    assert is_issue_from_source(rel_src, abs_src, manifest_dir) is True

    # Mismatched file name / included header
    assert is_issue_from_source("stdio.h", abs_src, manifest_dir) is False
    assert is_issue_from_source("other_file.c", abs_src, manifest_dir) is False


def test_juliet_runner_full():
    res = run_juliet_benchmark(MANIFEST_PATH, ci_only=False)
    assert res["total_test_cases_evaluated"] == 41
    assert res["failed_test_cases_count"] == 0
    ov = res["overall"]
    assert ov["tp"] + ov["fp"] + ov["tn"] + ov["fn"] > 0
    assert "precision" in ov
    assert "recall" in ov
    assert "f1" in ov

    by_cwe = res["by_cwe"]
    for cwe in CWES:
        assert cwe in by_cwe

    by_rule = res["by_rule"]
    for rule_id in {"CGULL-002", "CGULL-006", "CGULL-007", "CGULL-034"}:
        assert rule_id in by_rule
        assert by_rule[rule_id]["tp"] + by_rule[rule_id]["fp"] + by_rule[rule_id]["tn"] + by_rule[rule_id]["fn"] > 0

    assert by_rule["CGULL-002"]["fp"] == 0  # Juliet GoodSource/BadSink
    assert by_rule["CGULL-007"]["fn"] == 0  # Heap allocation capacity

    # Direct-NULL fixtures exercise CGULL-004 only. They must not inflate the
    # allocation-specific CGULL-003 denominator.
    direct_null_cases = [tc for tc in res["test_cases"] if tc["cwe"] == "CWE-476"]
    for tc in direct_null_cases:
        for oracle in tc["oracle_evaluations"]:
            assert set(oracle["by_rule"]) == {"CGULL-004"}

    # Only the interprocedural CWE-457 fixture reads the uninitialized pointer
    # as a call argument, so the other pointer fixtures are not CGULL-023 FNs.
    cwe457_cases = [tc for tc in res["test_cases"] if tc["cwe"] == "CWE-457"]
    for tc in cwe457_cases:
        expected = {"CGULL-021", "CGULL-023"} if tc["category"] == "interprocedural cases" else {"CGULL-021"}
        for oracle in tc["oracle_evaluations"]:
            assert set(oracle["by_rule"]) == expected
    assert by_rule["CGULL-023"]["tp"] == 1
    assert by_rule["CGULL-023"]["tn"] == 1
    assert by_rule["CGULL-023"]["fn"] == 0

    by_cat = res["by_category"]
    for cat in CATEGORIES:
        assert cat in by_cat


def test_juliet_runner_ci():
    res = run_juliet_benchmark(MANIFEST_PATH, ci_only=True)
    assert res["total_test_cases_evaluated"] == 17
    assert res["failed_test_cases_count"] == 0
    ov = res["overall"]
    assert ov["tp"] + ov["fp"] + ov["tn"] + ov["fn"] > 0


def test_juliet_runner_filters():
    # Filter by CWE
    res_cwe = run_juliet_benchmark(MANIFEST_PATH, cwe_filter="CWE-476")
    assert res_cwe["total_test_cases_evaluated"] == 9
    assert set(res_cwe["by_rule"]) == {"CGULL-004"}
    for tc in res_cwe["test_cases"]:
        assert tc["cwe"] == "CWE-476"

    # Filter by Category
    res_cat = run_juliet_benchmark(MANIFEST_PATH, category_filter="baseline")
    assert res_cat["total_test_cases_evaluated"] == 9
    for tc in res_cat["test_cases"]:
        assert tc["category"] == "baseline"

    # Filter by Test ID
    res_id = run_juliet_benchmark(MANIFEST_PATH, test_id_filter="CWE476_NULL_Pointer_Dereference__01_baseline")
    assert res_id["total_test_cases_evaluated"] == 1
    assert res_id["test_cases"][0]["id"] == "CWE476_NULL_Pointer_Dereference__01_baseline"


def test_juliet_runner_scan_failure_handling():
    mock_failed_res = ScanResult(
        target_path="mock.c",
        scanned_files_count=1,
        total_lines_of_code=10,
        total_issues_count=0,
        high_severity_count=0,
        medium_severity_count=0,
        low_severity_count=0,
        scan_duration_seconds=0.1,
        timestamp="2026-01-01T00:00:00Z",
        failed_paths=["mock.c"],
        files_failed=1,
        scan_errors=[ScanError("mock.c", "ParseError", "Failed to parse syntax")],
    )

    with patch("cgull.engine.CGullScanner.scan_path", return_value=mock_failed_res):
        res = run_juliet_benchmark(MANIFEST_PATH, test_id_filter="CWE476_NULL_Pointer_Dereference__01_baseline")
        assert res["total_test_cases_evaluated"] == 1
        assert res["failed_test_cases_count"] == 1
        tc_res = res["test_cases"][0]
        assert tc_res["status"] == "failed"
        assert len(tc_res["scan_errors"]) == 1
        assert tc_res["scan_errors"][0]["error_type"] == "ParseError"


def test_juliet_runner_missing_function_validation():
    bad_manifest = {
        "suite": "Bad Juliet Benchmark",
        "version": "1.0",
        "test_cases": [
            {
                "id": "CWE476_NULL_Pointer_Dereference__01_baseline",
                "cwe": "CWE-476",
                "category": "baseline",
                "file": "testcases/CWE476_NULL_Pointer_Dereference__01_baseline.c",
                "oracle": [
                    {
                        "function": "non_existent_function_name",
                        "vulnerable": True,
                        "expected_cwe": "CWE-476"
                    }
                ]
            }
        ]
    }

    manifest_file = os.path.join(REPO_ROOT, "benchmarks", "juliet", "test_missing_fn.json")
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(bad_manifest, f)

    try:
        with pytest.raises(ValueError) as excinfo:
            run_juliet_benchmark(manifest_file)
        assert "non_existent_function_name" in str(excinfo.value)
    finally:
        if os.path.exists(manifest_file):
            os.remove(manifest_file)


def test_juliet_runner_cli_thresholds():
    # Test passing thresholds
    test_args = ["run_juliet.py", "--ci", "--min-precision", "0.5", "--min-f1", "0.5"]
    with patch.object(sys, "argv", test_args):
        main()

    # Test failing threshold
    failing_args = ["run_juliet.py", "--ci", "--min-f1", "1.01"]
    with patch.object(sys, "argv", failing_args):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1


def test_juliet_runner_formatters():
    res = run_juliet_benchmark(MANIFEST_PATH, ci_only=True)
    text_rep = format_text_report(res)
    assert "C-GULL Juliet Benchmark Results" in text_rep
    assert "Overall Metrics:" in text_rep
    assert "Results by CWE:" in text_rep
    assert "Results by Rule:" in text_rep
    assert "Results by Control-Flow Category:" in text_rep

    md_rep = format_markdown_report(res)
    assert "# C-GULL Juliet Benchmark Results" in md_rep
    assert "## Overall Metrics" in md_rep
    assert "## Results by CWE" in md_rep
    assert "## Results by Rule" in md_rep
    assert "## Results by Control-Flow Category" in md_rep
