"""Regression coverage for #390 integer expression typing at conversion sinks."""

from cgull import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def _scan(tmp_path, body: str):
    source = tmp_path / "case.c"
    source.write_text(
        "typedef unsigned long size_t;\n"
        "void *malloc(size_t);\n" + body,
        encoding="utf-8",
    )
    scanner = CGullScanner(
        rules=[IntegerNarrowingCastRule()],
        engine_mode=AnalysisEngine.AST,
    )
    return scanner.scan_path(str(source), quiet=True).issues


def _cwes(issues):
    return [(issue.line_number, issue.cwe_id) for issue in issues]


def test_signed_arithmetic_argument_is_not_lost(tmp_path):
    issues = _scan(tmp_path, "void f(int n) { malloc(n + 1); }\n")
    assert _cwes(issues) == [(3, "CWE-195")]


def test_shift_and_conditional_expressions_preserve_signed_type(tmp_path):
    issues = _scan(
        tmp_path,
        "void shifted(int n) { malloc(n << 1); }\n"
        "void conditional(int flag, int n) { malloc(flag ? n : 1); }\n",
    )
    assert _cwes(issues) == [(3, "CWE-195"), (4, "CWE-195")]


def test_narrow_operands_are_promoted_before_result_conversion(tmp_path):
    issues = _scan(
        tmp_path,
        "void f(unsigned char a, unsigned char b) {\n"
        "    unsigned char result = a + b;\n"
        "}\n",
    )
    # Both operands promote to int before addition. CGULL-049 intentionally
    # gives signedness-change classification precedence over width narrowing,
    # so the subsequent int -> unsigned char conversion is CWE-195.
    assert _cwes(issues) == [(4, "CWE-195")]


def test_guarded_arithmetic_range_suppresses_signed_to_unsigned_finding(tmp_path):
    issues = _scan(
        tmp_path,
        "void f(int n) {\n"
        "    if (n < 0 || n > 100) return;\n"
        "    malloc(n + 1);\n"
        "}\n",
    )
    assert issues == []


def test_explicit_unsigned_cast_owns_conversion_without_duplicate(tmp_path):
    issues = _scan(tmp_path, "void f(int n) { malloc((unsigned int)n); }\n")
    assert _cwes(issues) == [(3, "CWE-195")]
