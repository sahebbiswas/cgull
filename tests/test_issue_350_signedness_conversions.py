import pytest

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def scan(body, parameters="int x, unsigned int u"):
    ctx = CASTParser().parse(f"void sink(unsigned int value) {{}} void f({parameters}) {{ {body} }}")
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue350.c", ctx)


@pytest.mark.parametrize("body,cwe", [
    ("unsigned int y = x;", "CWE-195"),
    ("unsigned long y = x;", "CWE-195"),
    ("unsigned int y = (unsigned int)x;", "CWE-195"),
    ("unsigned int y; y = x;", "CWE-195"),
    ("sink(x);", "CWE-195"),
    ("int y = u;", "CWE-196"),
    ("int y = (int)u;", "CWE-196"),
    ("int y; y = u;", "CWE-196"),
    ("short y = u;", "CWE-196"),
    ("unsigned int y = -1;", "CWE-195"),
    ("int y = 2147483648U;", "CWE-196"),
])
def test_unsafe_conversions_have_direction_specific_cwe(body, cwe):
    issues = scan(body)
    assert len(issues) == 1
    assert issues[0].cwe_id == cwe
    assert issues[0].rule_id == "CGULL-049"


@pytest.mark.parametrize("body", [
    "unsigned int y = 0;",
    "int y = 2147483647U;",
    "unsigned int y = 2147483647;",
    "long long y = u;",
    "if (x >= 0) { unsigned int y = x; }",
    "if (x < 0) return; unsigned int y = x;",
    "if (u <= INT_MAX) { int y = u; }",
    "if (u > INT_MAX) return; int y = u;",
    "if (INT_MAX >= u) { int y = u; }",
    "if (x >= 0 && x <= 255) { unsigned char y = x; }",
    "x = 42; unsigned int y = x;",
    "u = 42; int y = u;",
    "if (x >= 0) sink(x);",
    "if (x < u) {}",
])
def test_representable_values_and_comparisons_are_clean(body):
    assert scan(body) == []


@pytest.mark.parametrize("body", [
    "if (x >= 0) {} unsigned int y = x;",
    "if (x >= 0) { x = -1; unsigned int y = x; }",
    "if (u <= INT_MAX) { u = 2147483648U; int y = u; }",
    "if (x <= 255) { unsigned char y = x; }",
    "if (x >= 0) { unsigned char y = x; }",
])
def test_partial_or_stale_bounds_do_not_suppress(body):
    assert len(scan(body)) == 1


def test_typedef_signedness_and_safe_widening():
    ctx = CASTParser().parse("""
        typedef signed int signed_t;
        typedef unsigned int unsigned_t;
        void f(signed_t x, unsigned_t u, unsigned char byte) {
            unsigned_t a = x;
            signed_t b = u;
            int safe = byte;
        }
    """)
    issues = IntegerNarrowingCastRule().scan_ast("types.c", ctx)
    assert [issue.cwe_id for issue in issues] == ["CWE-195", "CWE-196"]


def test_nested_cast_retains_both_distinct_unsafe_conversions():
    issues = scan("int y = (unsigned int)-1;")
    assert [issue.cwe_id for issue in issues] == ["CWE-196", "CWE-195"]


def test_width_only_conversion_keeps_cwe_197():
    assert scan("short y = x;")[0].cwe_id == "CWE-197"


def test_unsigned_zero_guard_does_not_prove_signed_nonnegativity():
    assert len(scan("if (x >= 0U) { unsigned int y = x; }")) == 1


def test_comparison_rule_remains_distinct():
    from cgull.rules.types_and_arrays.signed_unsigned_comparison import SignedUnsignedComparisonRule
    assert scan("if (x < u) {}") == []
    ctx = CASTParser().parse("void f(int x, unsigned int u) {\n    if (x < u) {}\n}")
    findings = SignedUnsignedComparisonRule().scan_ast("comparison.c", ctx)
    assert findings and all(item.rule_id == "CGULL-033" for item in findings)


@pytest.mark.parametrize("mutation", ["mutate(&x);", "int *p = &x; *p = -1;", "int *p = &x; mutate(p);"])
def test_mutation_through_address_invalidates_guard(mutation):
    assert len(scan(f"if (x >= 0) {{ {mutation} unsigned int y = x; }}")) == 1
