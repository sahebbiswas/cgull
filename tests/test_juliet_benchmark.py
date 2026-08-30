"""
Unit tests for NIST Juliet Security Benchmark suite and runner.
"""

import os
import sys
import json
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmarks.run_juliet import (
    run_juliet_benchmark,
    compute_metrics,
    format_text_report,
    format_markdown_report,
    CATEGORIES,
    CWES,
)

MANIFEST_PATH = os.path.join(REPO_ROOT, "benchmarks", "juliet", "manifest.json")


def test_manifest_structure_and_validity():
    assert os.path.exists(MANIFEST_PATH), "Manifest file does not exist"
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert "test_cases" in manifest
    test_cases = manifest["test_cases"]
    assert len(test_cases) == 36

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
        for o in tc["oracle"]:
            assert "function" in o
            assert "vulnerable" in o
            assert isinstance(o["vulnerable"], bool)
            assert "expected_cwe" in o


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


def test_juliet_runner_full():
    res = run_juliet_benchmark(MANIFEST_PATH, ci_only=False)
    assert res["total_test_cases_evaluated"] == 36
    ov = res["overall"]
    assert ov["tp"] + ov["fp"] + ov["tn"] + ov["fn"] > 0
    assert "precision" in ov
    assert "recall" in ov
    assert "f1" in ov

    by_cwe = res["by_cwe"]
    for cwe in CWES:
        assert cwe in by_cwe

    by_cat = res["by_category"]
    for cat in CATEGORIES:
        assert cat in by_cat


def test_juliet_runner_ci():
    res = run_juliet_benchmark(MANIFEST_PATH, ci_only=True)
    assert res["total_test_cases_evaluated"] == 12
    ov = res["overall"]
    assert ov["tp"] + ov["fp"] + ov["tn"] + ov["fn"] > 0


def test_juliet_runner_filters():
    # Filter by CWE
    res_cwe = run_juliet_benchmark(MANIFEST_PATH, cwe_filter="CWE-476")
    assert res_cwe["total_test_cases_evaluated"] == 9
    for tc in res_cwe["test_cases"]:
        assert tc["cwe"] == "CWE-476"

    # Filter by Category
    res_cat = run_juliet_benchmark(MANIFEST_PATH, category_filter="baseline")
    assert res_cat["total_test_cases_evaluated"] == 4
    for tc in res_cat["test_cases"]:
        assert tc["category"] == "baseline"

    # Filter by Test ID
    res_id = run_juliet_benchmark(MANIFEST_PATH, test_id_filter="CWE476_NULL_Pointer_Dereference__01_baseline")
    assert res_id["total_test_cases_evaluated"] == 1
    assert res_id["test_cases"][0]["id"] == "CWE476_NULL_Pointer_Dereference__01_baseline"


def test_juliet_runner_formatters():
    res = run_juliet_benchmark(MANIFEST_PATH, ci_only=True)
    text_rep = format_text_report(res)
    assert "C-GULL Juliet Benchmark Results" in text_rep
    assert "Overall Metrics:" in text_rep
    assert "Results by CWE:" in text_rep
    assert "Results by Control-Flow Category:" in text_rep

    md_rep = format_markdown_report(res)
    assert "# C-GULL Juliet Benchmark Results" in md_rep
    assert "## Overall Metrics" in md_rep
    assert "## Results by CWE" in md_rep
    assert "## Results by Control-Flow Category" in md_rep
