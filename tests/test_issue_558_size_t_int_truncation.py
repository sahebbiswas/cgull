"""Regressions for #558: size_t→int truncation (cJSON_GetArraySize pattern)."""

from pathlib import Path

from cgull.ast_analyzer import CASTParser, is_integer_narrowing_conversion
from cgull.cfg import integer_type_range
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


FIXTURES = Path(__file__).parent / "rules" / "CGULL-049"


def _scan(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue_558.c", ctx)


def test_fake_libc_size_t_typedef_int_preserves_unsigned_range():
    """pycparser fake_libc's ``typedef int size_t`` must not erase unsignedness."""
    code = """
typedef int size_t;
int truncate(size_t size) {
    return (int)size;
}
"""
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    assert ctx.typedef_shapes.get("size_t") is not None
    assert ctx.typedef_shapes["size_t"].target == "int"
    bounds = integer_type_range("size_t", ctx)
    assert bounds is not None
    assert bounds.lower == 0
    assert bounds.upper is not None and bounds.upper > 2**31 - 1
    assert is_integer_narrowing_conversion("size_t", "int", ctx) is True
    issues = IntegerNarrowingCastRule().scan_ast("fake_size_t.c", ctx)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-049"
    assert issues[0].cwe_id in {"CWE-196", "CWE-197"}


def test_get_array_size_accumulate_then_cast_is_reported():
    code = (FIXTURES / "accumulate_size_t_to_int.c").read_text()
    issues = _scan(code)
    lines = sorted({issue.line_number for issue in issues if issue.rule_id == "CGULL-049"})
    assert lines == [18, 31, 36]


def test_int_max_guard_suppresses_size_t_to_int():
    code = (FIXTURES / "accumulate_size_t_to_int_guarded.c").read_text()
    assert _scan(code) == []
