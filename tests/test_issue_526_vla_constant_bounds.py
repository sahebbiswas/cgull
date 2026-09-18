"""Regression coverage for issue #526: constant-foldable CGULL-010 bounds."""

import pytest

from cgull.ast_analyzer import CASTParser
from cgull.rules import get_rule_by_id


def _issues(source: str, *, fallback: bool):
    parser = CASTParser()
    if fallback:
        parser._try_pycparser = lambda *args, **kwargs: (
            None,
            False,
            "regex-fallback",
        )
    context = parser.parse(source)
    assert context.has_pycparser is (not fallback)
    return get_rule_by_id("CGULL-010").scan_ast("issue_526.c", context)


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize(
    "bound",
    [
        "512 * 2",
        "1 << 10",
        "(256 * 4)",
        "((8 + 8) * (4 | 1))",
    ],
)
def test_constant_foldable_bounds_are_not_vlas(fallback, bound):
    source = f"void f(void) {{\n    char a[{bound}];\n    use(a);\n}}"
    assert _issues(source, fallback=fallback) == []


@pytest.mark.parametrize("fallback", [False, True])
def test_object_macro_constant_expression_is_not_vla(fallback):
    source = """#define SIZE (256 * 4)
void f(void) {
    char a[SIZE];
    use(a);
}
"""
    assert _issues(source, fallback=fallback) == []


@pytest.mark.parametrize("fallback", [False, True])
def test_runtime_expression_remains_vla_and_preserves_bound(fallback):
    source = """void f(int n) {
    char a[n * 2];
    use(a);
}
"""
    issues = _issues(source, fallback=fallback)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-010"
    assert "a[n * 2]" in issues[0].message


@pytest.mark.parametrize("fallback", [False, True])
def test_const_object_bound_remains_vla_in_c(fallback):
    source = """void f(void) {
    const int n = 8;
    char a[n];
    use(a);
}
"""
    issues = _issues(source, fallback=fallback)
    assert len(issues) == 1
    assert "a[n]" in issues[0].message
