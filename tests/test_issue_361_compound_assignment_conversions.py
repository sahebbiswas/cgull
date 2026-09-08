import pytest

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def _scan(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue_361.c", ctx)


@pytest.mark.parametrize(
    "operator",
    ["+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="],
)
def test_detects_all_supported_compound_assignment_operator_families(operator):
    code = f"""
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(uint8_t small, uint32_t wide) {{
    small {operator} wide;
}}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].line_number == 5
    assert issues[0].rule_id == "CGULL-049"
    assert f"Compound assignment '{operator}' to 'small'" in issues[0].message


@pytest.mark.parametrize("ctype", ["short", "signed char"])
def test_signed_operand_promotion_is_not_reported_as_sign_extension(ctype):
    code = f"""
void f({ctype} a, {ctype} b) {{
    a += b;
}}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].cwe_id == "CWE-197"
    assert "result conversion" in issues[0].message
    assert "operand conversion" not in issues[0].message


def test_detects_wider_signed_rhs_converted_back_to_narrow_signed_lhs():
    code = """
void f(signed char small, int wide) {
    small += wide;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].cwe_id == "CWE-197"
    assert "'int'" in issues[0].message
    assert "'signed char'" in issues[0].message


def test_detects_wider_unsigned_rhs_converted_back_to_narrow_lhs():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(uint8_t small, uint32_t wide) {
    small += wide;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].cwe_id == "CWE-197"
    assert "'uint32_t'" in issues[0].message
    assert "'uint8_t'" in issues[0].message


def test_detects_negative_signed_rhs_conversion_during_uac():
    code = """
typedef unsigned long long uint64_t;
typedef signed int int32_t;
void f(uint64_t total, int32_t delta) {
    total += delta;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].cwe_id == "CWE-195"
    assert "operand conversion" in issues[0].message
    assert "negative value to unsigned" in issues[0].message


def test_detects_unsigned_result_converted_back_to_signed_lhs():
    code = """
typedef signed int int32_t;
typedef unsigned int uint32_t;
void f(int32_t total, uint32_t delta) {
    total += delta;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].cwe_id == "CWE-196"
    assert "result conversion" in issues[0].message


def test_shift_result_is_converted_back_to_narrow_destination():
    code = """
typedef unsigned char uint8_t;
void f(uint8_t value, unsigned int shift) {
    value <<= shift;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].cwe_id == "CWE-195"
    assert "negative value to unsigned" in issues[0].message
    assert "'int'" in issues[0].message
    assert "'uint8_t'" in issues[0].message


def test_safe_constant_compound_result_is_suppressed():
    code = """
typedef unsigned char uint8_t;
void f(void) {
    uint8_t value = 1;
    value += 2;
}
"""
    assert _scan(code) == []


def test_range_guard_that_proves_final_result_safe_is_suppressed():
    code = """
typedef unsigned char uint8_t;
void f(uint8_t value) {
    if (value <= 250) {
        value += 5;
    }
}
"""
    assert _scan(code) == []


def test_explicit_cast_inside_compound_assignment_is_not_double_reported():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(uint8_t value, uint32_t wide) {
    value += (uint8_t)wide;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].message.startswith("Explicit integer cast")


def test_non_integer_compound_assignment_degrades_cleanly():
    code = """
void f(int *ptr, int offset) {
    ptr += offset;
}
"""
    assert _scan(code) == []
