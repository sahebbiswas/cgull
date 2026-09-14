from benchmarks.check_juliet_regression import evaluate_regression, format_markdown


BASELINE = {
    "rule_id": "CGULL-049",
    "default_max_drop": 0.02,
    "max_failed_files": 0,
    "cwes": {
        "CWE-194": {"precision": 0.50, "recall": 0.75, "f1": 0.60},
        "CWE-197": {
            "precision": 0.80,
            "recall": 0.70,
            "f1": 0.74,
            "max_precision_drop": 0.01,
        },
    },
}


def _report(cwe_194=None, cwe_197=None, failed_files=None):
    return {
        "failed_files": failed_files or [],
        "by_cwe": {
            "CWE-194": cwe_194 or {"precision": 0.49, "recall": 0.74, "f1": 0.59},
            "CWE-197": cwe_197 or {"precision": 0.79, "recall": 0.69, "f1": 0.73},
        },
    }


def test_budget_accepts_metrics_within_allowed_drop():
    rows, failures = evaluate_regression(_report(), BASELINE)
    assert failures == []
    rendered = format_markdown(rows, failures)
    assert "CGULL-049" in rendered
    assert "CWE-194" in rendered
    assert "CWE-197" in rendered
    assert "Result: PASS" in rendered


def test_metric_specific_budget_rejects_excess_precision_drop():
    report = _report(
        cwe_197={"precision": 0.7899, "recall": 0.70, "f1": 0.74},
    )
    _, failures = evaluate_regression(report, BASELINE)
    assert any("CGULL-049/CWE-197" in failure and "precision" in failure for failure in failures)


def test_missing_cwe_row_fails_closed():
    report = _report()
    del report["by_cwe"]["CWE-197"]
    _, failures = evaluate_regression(report, BASELINE)
    assert failures == ["CGULL-049/CWE-197: metric row is missing from benchmark report"]


def test_failed_source_files_fail_gate():
    _, failures = evaluate_regression(_report(failed_files=["bad.c"]), BASELINE)
    assert any("failed files" in failure for failure in failures)
