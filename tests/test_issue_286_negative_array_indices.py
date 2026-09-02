"""Focused regression tests for issue #286 / CGULL-007."""

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import ArrayIndexOutOfBoundsRule


def _scan(code: str):
    ctx = CASTParser().parse(code)
    return ArrayIndexOutOfBoundsRule().scan_ast("issue_286.c", ctx)


def test_negative_constant_array_indices_are_reported():
    code = """
    int f(void) {
        int a[4] = {0};
        return a[-1] + a[-(1)] + a[0 - 1];
    }
    """
    issues = _scan(code)
    messages = [issue.message for issue in issues]
    assert sum("index [-1] is below zero" in message for message in messages) == 3


def test_nonnegative_constant_boundaries_remain_clean():
    code = """
    int f(void) {
        int a[4] = {0};
        return a[0] + a[4 - 1];
    }
    """
    assert _scan(code) == []


def test_unary_plus_constant_remains_clean():
    code = """
    int f(void) {
        int a[4] = {0};
        return a[+1];
    }
    """
    assert _scan(code) == []
