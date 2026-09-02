from pathlib import Path

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id
from tests.run_corpus import run_corpus_scan


REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPO_ROOT / "tests" / "rules"
JULIET_CASE = (
    REPO_ROOT
    / "benchmarks"
    / "juliet"
    / "testcases"
    / "CWE134_Uncontrolled_Format_String__printf_01_baseline.c"
)


def test_cgull_002_precision_corpus_has_no_false_positives_or_false_negatives():
    success, report = run_corpus_scan(str(RULES_DIR), target_rule_id="CGULL-002")
    assert success, report
    assert "Missing Findings (FN)  : 0" in report
    assert "Unexpected Findings(FP): 0" in report


def test_cgull_002_juliet_baseline_keeps_true_positive_and_suppresses_good_cases():
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-002")],
        engine_mode=AnalysisEngine.HYBRID,
    )
    result = scanner.scan_path(str(JULIET_CASE))

    findings = [(issue.line_number, issue.rule_id) for issue in result.issues]

    # Vulnerable Juliet case: a directive-bearing local format reaches printf.
    assert (11, "CGULL-002") in findings
    # Explicit format string and GoodSource/BadSink fixed-literal variant remain clean.
    assert all(line not in {16, 22} for line, _ in findings)
    assert len(findings) == 1
