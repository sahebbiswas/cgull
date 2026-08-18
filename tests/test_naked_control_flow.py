"""
Unit tests for CGULL-013 Naked Control Flow Statements Rule.
Tests preprocessor filtering, multiline compound conditions, and true positive naked statements.
"""

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


def run_cgull_rule(rule_name: str, code: str):
    rule = get_rule_by_id("CGULL-013")
    scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
    return scanner.scan_text(code, "test.c").issues


def test_naked_control_flow_with_intervening_preprocessor():
    code = """
    if (a) {
        foo();
    } else
    #endif
    {
        bar();
    }
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"


def test_naked_control_flow_multiline_compound_if():
    code = """
    if (this_condition
        && that_condition)
    {
        do_work();
    }
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"


def test_naked_control_flow_true_positive_still_flags():
    code = """
    if (condition)
        naked_statement();
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 1
