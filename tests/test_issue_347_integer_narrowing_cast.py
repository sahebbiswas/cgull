from cgull.ast_analyzer import CASTParser, get_integer_type_byte_size, is_integer_narrowing_conversion
from cgull.models import FixType
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def _scan(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue_347.c", ctx)


def test_detects_signed_unsigned_and_fixed_width_narrowing_casts():
    code = """
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
void f(int wide, unsigned long uwide, uint32_t fixed) {
    short a = (short)wide;
    unsigned char b = (unsigned char)uwide;
    uint8_t c = (uint8_t)fixed;
}
"""
    issues = _scan(code)
    assert [issue.line_number for issue in issues] == [6, 7, 8]
    assert all(issue.rule_id == "CGULL-049" for issue in issues)
    assert all(issue.fix_type == FixType.MANUAL_REVIEW for issue in issues)


def test_same_width_and_widening_casts_are_not_reported():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(uint8_t small, int value, uint32_t same) {
    uint32_t a = (uint32_t)small;
    unsigned int b = (unsigned int)value;
    int c = (int)same;
}
"""
    assert _scan(code) == []


def test_non_integer_and_unresolved_types_are_not_speculated_about():
    code = """
typedef struct Payload { int value; } Payload;
void f(double value, Payload payload) {
    float a = (float)value;
    short b = (short)payload;
}
"""
    assert _scan(code) == []


def test_shared_integer_width_helper_reuses_resolved_type_sizes():
    ctx = CASTParser().parse("typedef unsigned char byte_t; void f(void) {}")
    assert get_integer_type_byte_size("byte_t", ctx) == 1
    assert get_integer_type_byte_size("double", ctx) is None
    assert get_integer_type_byte_size("void *", ctx) is None
    assert get_integer_type_byte_size("int[10]", ctx) is None
    assert get_integer_type_byte_size("char[256]", ctx) is None
    assert is_integer_narrowing_conversion("unsigned int", "unsigned char", ctx) is True
    assert is_integer_narrowing_conversion("unsigned char", "unsigned int", ctx) is False
    assert is_integer_narrowing_conversion("double", "unsigned char", ctx) is None
    assert is_integer_narrowing_conversion("int[10]", "unsigned char", ctx) is None
