"""CGULL-004 must flag additive pointer arithmetic on maybe-NULL pointers (#559)."""

import pytest

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


def scan(code):
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-004")],
        engine_mode=AnalysisEngine.AST,
    )
    return scanner.scan_text(code, "issue_559.c").issues


def test_param_plus_offset_reports():
    code = """
    const char *f(const char *p, int off) {
        return p + off;
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "pointer arithmetic" in issues[0].message
    assert "p" in issues[0].message


def test_offset_plus_param_reports():
    code = """
    const char *f(const char *p, int off) {
        return off + p;
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "pointer arithmetic" in issues[0].message


def test_array_index_still_reports():
    code = """
    char f(char *p, int off) {
        return p[off];
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "dereferenced" in issues[0].message


def test_known_null_local_plus_offset_reports():
    code = """
    const char *f(int off) {
        char *p = 0;
        return p + off;
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "known to be NULL" in issues[0].message
    assert "pointer arithmetic" in issues[0].message


def test_star_plus_index_reports():
    code = """
    int f(int *p, int i) {
        return *(p + i);
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "p" in issues[0].message


def test_guarded_pointer_plus_is_silent():
    code = """
    const char *f(const char *p, int off) {
        if (p) return p + off;
        return 0;
    }
    """
    assert scan(code) == []


def test_early_return_guard_before_arith_is_silent():
    code = """
    const char *f(const char *p, int off) {
        if (p == 0) return 0;
        return p + off;
    }
    """
    assert scan(code) == []


def test_integer_addition_is_silent():
    code = """
    int f(int a, int b) {
        return a + b;
    }
    """
    assert scan(code) == []


def test_short_circuit_guards_arith_in_condition():
    code = """
    int f(const char *p, int n, const char *end) {
        if (p == 0 || p + n > end) {
            return 0;
        }
        return 1;
    }
    """
    assert scan(code) == []


def test_integer_zero_addition_is_not_pointer_arithmetic():
    """Sourcery: int a = 0; return a + b must not fire CGULL-004."""
    code = """
    int f(int b) {
        int a = 0;
        return a + b;
    }
    """
    assert scan(code) == []


def test_pointer_minus_integer_on_maybe_null_reports():
    code = """
    const char *f(const char *p, int off) {
        return p - off;
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "pointer arithmetic" in issues[0].message.lower() or "arithmetic" in issues[0].message.lower()
