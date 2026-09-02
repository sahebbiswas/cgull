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
        int x = a[-1];
        x += a[-(1)];
        x += a[0 - 1];
        return x;
    }
    """
    issues = _scan(code)
    messages = [issue.message for issue in issues]
    assert sum("index [-1] is below zero" in message for message in messages) == 3


def test_multiple_negative_subscripts_on_one_line_are_reported_separately():
    code = """
    int f(void) {
        int a[4] = {0};
        int b[4] = {0};
        return a[-1] + b[-2];
    }
    """
    issues = _scan(code)
    messages = [issue.message for issue in issues]
    assert len(issues) == 2
    assert any("index [-1] is below zero" in message and "'a[4]'" in message for message in messages)
    assert any("index [-2] is below zero" in message and "'b[4]'" in message for message in messages)
    assert len({issue.column_number for issue in issues}) == 2


def test_unsigned_cast_of_negative_constant_is_not_mislabeled_as_negative():
    code = """
    int f(void) {
        int a[4] = {0};
        return a[(unsigned)-1];
    }
    """
    issues = _scan(code)
    assert all("below zero" not in issue.message for issue in issues)


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
