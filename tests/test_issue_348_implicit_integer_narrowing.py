from cgull.ast_analyzer import CASTParser
from cgull.models import FixType
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def _scan(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue_348.c", ctx)


def test_detects_implicit_declaration_and_assignment_narrowing():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(uint32_t wide) {
    uint8_t declared = wide;
    uint8_t assigned = 0;
    assigned = wide;
}
"""
    issues = _scan(code)
    assert [issue.line_number for issue in issues] == [5, 7]
    assert all(issue.rule_id == "CGULL-049" for issue in issues)
    assert all(issue.fix_type == FixType.MANUAL_REVIEW for issue in issues)


def test_detects_direct_argument_binding_when_parameter_type_is_known():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void write_reg(uint8_t value) { (void)value; }
void caller(uint32_t wide) {
    write_reg(wide);
}
"""
    issues = _scan(code)
    assert [issue.line_number for issue in issues] == [6]
    assert "parameter 'value'" in issues[0].message


def test_same_width_and_widening_implicit_conversions_are_clean():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void take32(uint32_t value) { (void)value; }
void f(uint8_t small, uint32_t same) {
    uint32_t a = small;
    uint32_t b = same;
    a = same;
    take32(small);
}
"""
    assert _scan(code) == []


def test_typedefs_and_parameter_sources_are_resolved():
    code = """
typedef unsigned char byte_t;
typedef unsigned long word_t;
void sink(byte_t value) { (void)value; }
void f(word_t parameter) {
    byte_t local = parameter;
    sink(parameter);
}
"""
    issues = _scan(code)
    assert [issue.line_number for issue in issues] == [6, 7]


def test_unresolved_callee_is_ignored_conservatively():
    code = """
typedef unsigned int uint32_t;
void f(uint32_t wide) {
    external_sink(wide);
}
"""
    assert _scan(code) == []


def test_explicit_cast_is_not_double_reported_by_implicit_paths():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void sink(uint8_t value) { (void)value; }
void f(uint32_t wide) {
    uint8_t a = (uint8_t)wide;
    a = (uint8_t)wide;
    sink((uint8_t)wide);
}
"""
    issues = _scan(code)
    assert [issue.line_number for issue in issues] == [6, 7, 8]
    assert all(issue.message.startswith("Explicit integer cast") for issue in issues)


def test_compound_assignment_is_not_speculated_about_in_drop_two():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(uint8_t small, uint32_t wide) {
    small += wide;
}
"""
    assert _scan(code) == []
