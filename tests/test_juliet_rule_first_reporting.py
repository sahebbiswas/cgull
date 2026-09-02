"""Regression tests for rule-first Juliet benchmark reporting."""

import json
import os

from benchmarks.run_juliet import (
    format_markdown_report,
    format_text_report,
    run_juliet_benchmark,
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MANIFEST_PATH = os.path.join(REPO_ROOT, "benchmarks", "juliet", "manifest.json")


def _results():
    metrics = {
        "tp": 1,
        "fp": 0,
        "tn": 1,
        "fn": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }
    return {
        "suite": "test",
        "version": "1.0",
        "total_test_cases_evaluated": 1,
        "failed_test_cases_count": 0,
        "filters": {},
        "overall": metrics,
        "by_rule": {"CGULL-023": metrics},
        "by_cwe": {"CWE-457": metrics},
        "by_category": {"baseline": metrics},
        "test_cases": [],
    }


def test_text_report_shows_rule_table_before_cwe_table():
    report = format_text_report(_results())
    assert report.index("Results by Rule:") < report.index("Results by CWE:")


def test_markdown_report_shows_rule_table_before_cwe_table():
    report = format_markdown_report(_results())
    assert report.index("## Results by Rule") < report.index("## Results by CWE")


def test_json_report_serializes_production_rule_metrics_before_cwe_metrics():
    results = run_juliet_benchmark(MANIFEST_PATH, ci_only=True)
    keys = list(results)
    assert keys.index("by_rule") < keys.index("by_cwe")

    report = json.dumps(results, indent=2)
    assert report.index('"by_rule"') < report.index('"by_cwe"')
