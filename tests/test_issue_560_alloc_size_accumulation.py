"""CGULL-006: allocation-size accumulation after partial INT_MAX gates (#560)."""

from types import SimpleNamespace

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id
from cgull.rules.types_and_arrays.arithmetic_integer_overflow import ArithmeticIntegerOverflowRule


def _scan_ast(body: str, params=()):
    lines = body.splitlines()
    fn = SimpleNamespace(
        body=body,
        start_line=1,
        body_start_line=1,
        parameters=tuple(SimpleNamespace(name=name) for name in params),
    )
    ctx = SimpleNamespace(functions=(fn,), source_lines=lines)
    return ArithmeticIntegerOverflowRule().scan_ast("issue_560.c", ctx)


def _scan_rule(code: str):
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-006")],
        engine_mode=AnalysisEngine.AST,
    )
    return scanner.scan_text(code, "issue_560.c").issues


def test_ensure_style_intmax_then_accum_reports():
    """Partial INT_MAX gate must not prove post-add size safety before realloc."""
    issues = _scan_ast(
        "size_t needed = n;\n"
        "if (needed > INT_MAX) {\n"
        "return NULL;\n"
        "}\n"
        "needed += p->offset + 1;\n"
        "if (needed <= p->length) {\n"
        "return p->buffer + p->offset;\n"
        "}\n"
        "newsize = needed * 2;\n"
        "newbuffer = realloc(p->buffer, newsize);\n"
    )
    accum = [i for i in issues if "allocation-size accumulation" in i.message]
    assert len(accum) >= 1
    assert any(i.line_number == 5 for i in accum)
    assert any("INT_MAX-style gate" in i.message for i in accum)


def test_partial_intmax_does_not_suppress_realloc_add_arg():
    issues = _scan_ast(
        "if (needed > INT_MAX) return NULL;\n"
        "char *p = realloc(buf, needed + offset);\n"
    )
    assert len(issues) == 1
    assert issues[0].line_number == 2
    assert "memory allocation argument" in issues[0].message
    assert "INT_MAX-style gate" in issues[0].message


def test_size_max_guard_suppresses_realloc_add_arg():
    issues = _scan_ast(
        "if (needed > SIZE_MAX - offset) return NULL;\n"
        "char *p = realloc(buf, needed + offset);\n"
    )
    alloc_issues = [i for i in issues if "memory allocation argument" in i.message]
    assert alloc_issues == []


def test_size_max_guard_before_accum_is_silent():
    issues = _scan_ast(
        "if (needed > SIZE_MAX - (offset + 1)) return NULL;\n"
        "needed += offset + 1;\n"
        "void *p = realloc(buf, needed);\n"
    )
    assert [i for i in issues if "allocation-size accumulation" in i.message] == []


def test_max_elements_guard_still_suppresses_mult_alloc():
    issues = _scan_ast(
        "if (count > MAX_ELEMENTS) return;\n"
        "int *buf = malloc(count * sizeof(int));\n"
    )
    assert issues == []


def test_unchecked_offset_accum_feeding_realloc_reports():
    issues = _scan_ast(
        "needed += offset;\n"
        "void *p = realloc(buf, needed);\n"
    )
    assert len(issues) == 1
    assert "allocation-size accumulation" in issues[0].message


def test_constant_bump_without_partial_gate_is_silent():
    issues = _scan_ast(
        "size_t n = 10;\n"
        "n += 1;\n"
        "void *p = malloc(n);\n"
    )
    assert issues == []


def test_scanner_ensure_style_fixture():
    code = """
    #include <stdlib.h>
    #include <limits.h>
    typedef struct {
        unsigned char *buffer;
        size_t length;
        size_t offset;
    } printbuffer;
    static unsigned char *ensure(printbuffer *p, size_t needed) {
        unsigned char *newbuffer;
        size_t newsize;
        if (needed > INT_MAX) {
            return 0;
        }
        needed += p->offset + 1;
        if (needed <= p->length) {
            return p->buffer + p->offset;
        }
        newsize = needed * 2;
        newbuffer = (unsigned char *)realloc(p->buffer, newsize);
        return newbuffer;
    }
    """
    issues = _scan_rule(code)
    assert any("allocation-size accumulation" in i.message for i in issues)
