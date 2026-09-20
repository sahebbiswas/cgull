"""Regressions for #558: size_t→int truncation (cJSON_GetArraySize pattern)."""

from pathlib import Path

from cgull.ast_analyzer import CASTParser, is_integer_narrowing_conversion
from cgull.ast_analyzer.integer_types import restore_fake_libc_unsigned_source_type
from cgull.cfg import integer_type_range
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


FIXTURES = Path(__file__).parent / "rules" / "CGULL-049"


def _scan(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue_558.c", ctx)


def test_fake_libc_size_t_source_to_signed_restores_unsigned_semantics():
    """fake_libc ``typedef int size_t`` must still detect size_t→int (CWE-196)."""
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
    # Global resolution stays faithful to the typedef (avoids CWE-195 FPs).
    raw_bounds = integer_type_range("size_t", ctx)
    assert raw_bounds is not None
    assert raw_bounds.lower < 0
    # Source→signed restore recovers ISO unsignedness for conversion analysis.
    restored = restore_fake_libc_unsigned_source_type("size_t", "int", ctx)
    assert restored == "unsigned long"
    bounds = integer_type_range(restored, ctx)
    assert bounds is not None
    assert bounds.lower == 0
    assert bounds.upper is not None and bounds.upper > 2**31 - 1
    assert is_integer_narrowing_conversion(restored, "int", ctx) is True
    issues = IntegerNarrowingCastRule().scan_ast("fake_size_t.c", ctx)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-049"
    assert issues[0].cwe_id == "CWE-196"


def test_fake_libc_size_t_as_destination_does_not_report_signed_to_unsigned():
    """Juliet CWE-195 style: signed→size_t must stay quiet under fake_libc int."""
    code = """
typedef int size_t;
void *malloc(size_t n);
void sink(int data) {
    if (data < 100) {
        char *buf = (char *)malloc(data);
        (void)buf;
    }
}
"""
    assert _scan(code) == []


def test_get_array_size_accumulate_then_cast_is_reported():
    code = (FIXTURES / "accumulate_size_t_to_int.c").read_text()
    issues = _scan(code)
    lines = sorted({issue.line_number for issue in issues if issue.rule_id == "CGULL-049"})
    assert lines == [18, 31, 36]
    assert all(issue.cwe_id == "CWE-196" for issue in issues if issue.rule_id == "CGULL-049")


def test_int_max_guard_suppresses_size_t_to_int():
    code = (FIXTURES / "accumulate_size_t_to_int_guarded.c").read_text()
    assert _scan(code) == []
