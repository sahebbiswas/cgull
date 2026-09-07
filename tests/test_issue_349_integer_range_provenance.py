from cgull.ast_analyzer import CASTParser
from cgull.cfg import IntegerRange, analyze_integer_ranges, find_function_def
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def _parse(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return ctx


def _scan(code: str):
    return IntegerNarrowingCastRule().scan_ast("issue_349.c", _parse(code))


def _declaration(ctx, function_name: str, variable_name: str):
    from pycparser import c_ast

    funcdef = find_function_def(ctx.pycparser_ast, function_name)
    assert funcdef is not None
    found = []

    class Visitor(c_ast.NodeVisitor):
        def visit_Decl(self, node):
            if node.name == variable_name:
                found.append(node)
            self.generic_visit(node)

    Visitor().visit(funcdef)
    assert len(found) == 1
    return found[0]


def test_range_domain_propagates_constant_foldable_local_values():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(void) {
    uint32_t x = 40 + 2;
    uint8_t y = x;
}
"""
    ctx = _parse(code)
    analysis = analyze_integer_ranges(ctx, "f")
    declaration = _declaration(ctx, "f", "y")
    assert analysis is not None
    assert analysis.range_for_expression(declaration.init, declaration) == IntegerRange(42, 42)


def test_range_domain_keeps_dominating_guard_on_protected_path():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(uint32_t x) {
    if (x <= UINT8_MAX) {
        uint8_t y = x;
    }
}
"""
    ctx = _parse(code)
    analysis = analyze_integer_ranges(ctx, "f")
    declaration = _declaration(ctx, "f", "y")
    assert analysis is not None
    assert analysis.range_for_expression(declaration.init, declaration) == IntegerRange(0, 255)


def test_range_domain_drops_partial_path_guard_at_join():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void log_value(uint32_t value) { (void)value; }
void f(uint32_t x) {
    if (x <= UINT8_MAX)
        log_value(x);
    uint8_t y = x;
}
"""
    ctx = _parse(code)
    analysis = analyze_integer_ranges(ctx, "f")
    declaration = _declaration(ctx, "f", "y")
    assert analysis is not None
    assert analysis.range_for_expression(declaration.init, declaration) == IntegerRange(0, (1 << 32) - 1)


def test_range_domain_invalidates_guard_after_stale_assignment():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(uint32_t x) {
    if (x <= UINT8_MAX) {
        x = 1000;
        uint8_t y = x;
    }
}
"""
    ctx = _parse(code)
    analysis = analyze_integer_ranges(ctx, "f")
    declaration = _declaration(ctx, "f", "y")
    assert analysis is not None
    assert analysis.range_for_expression(declaration.init, declaration) == IntegerRange(1000, 1000)


def test_safe_constant_provenance_suppresses_cgull_049():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(void) {
    uint32_t x = 42;
    uint8_t y = x;
}
"""
    assert _scan(code) == []


def test_dominating_unsigned_upper_bound_suppresses_cgull_049():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(uint32_t x) {
    if (x <= UINT8_MAX) {
        uint8_t y = x;
    }
}
"""
    assert _scan(code) == []


def test_dominating_guard_suppresses_direct_argument_binding():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void sink(uint8_t value) { (void)value; }
void f(uint32_t x) {
    if (x <= UINT8_MAX)
        sink(x);
}
"""
    assert _scan(code) == []


def test_non_dominating_guard_does_not_suppress_cgull_049():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void log_value(uint32_t value) { (void)value; }
void f(uint32_t x) {
    if (x <= UINT8_MAX)
        log_value(x);
    uint8_t y = x;
}
"""
    issues = _scan(code)
    assert [issue.line_number for issue in issues] == [8]


def test_stale_guard_after_assignment_does_not_suppress_cgull_049():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void f(uint32_t x) {
    if (x <= UINT8_MAX) {
        x = 1000;
        uint8_t y = x;
    }
}
"""
    issues = _scan(code)
    assert [issue.line_number for issue in issues] == [7]


def test_signed_destination_requires_both_lower_and_upper_bounds():
    partial = """
typedef signed char int8_t;
typedef signed int int32_t;
void f(int32_t x) {
    if (x <= INT8_MAX) {
        int8_t y = x;
    }
}
"""
    full = """
typedef signed char int8_t;
typedef signed int int32_t;
void f(int32_t x) {
    if (x >= INT8_MIN && x <= INT8_MAX) {
        int8_t y = x;
    }
}
"""
    assert len(_scan(partial)) == 1
    assert _scan(full) == []


def test_unsigned_destination_rejects_negative_source_range_without_nonnegative_guard():
    unsafe = """
typedef unsigned char uint8_t;
typedef signed int int32_t;
void f(int32_t x) {
    if (x <= UINT8_MAX) {
        uint8_t y = x;
    }
}
"""
    safe = """
typedef unsigned char uint8_t;
typedef signed int int32_t;
void f(int32_t x) {
    if (x >= 0 && x <= UINT8_MAX) {
        uint8_t y = x;
    }
}
"""
    assert len(_scan(unsafe)) == 1
    assert _scan(safe) == []
