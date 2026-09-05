"""Regression coverage for issue #303 / CGULL-044 interprocedural bounds."""

from cgull.engine import CGullScanner
from cgull.models import Confidence
from cgull.rules.memory_management import MemcpyStructMemberOverflowRule


def _scan(code: str):
    scanner = CGullScanner(rules=[MemcpyStructMemberOverflowRule()])
    return scanner.scan_text(code, file_path="issue_303.c").issues


def test_reports_overflow_through_two_helpers():
    code = r"""
void memcpy(void *dst, const void *src, unsigned long n);

void leaf(char *dst, const char *src, unsigned long n) {
    memcpy(dst, src, n);
}
void middle(char *dst, const char *src, unsigned long n) {
    leaf(dst, src, n);
}
void entry(const char *src) {
    char buf[8];
    middle(buf, src, 12);
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].engine == "Interprocedural"
    assert "leaf -> memcpy" in issues[0].message
    assert "Provable out-of-bounds write" in issues[0].message


def test_suppresses_proven_safe_copy_through_two_helpers():
    code = r"""
void memcpy(void *dst, const void *src, unsigned long n);

void leaf(char *dst, const char *src, unsigned long n) {
    memcpy(dst, src, n);
}
void middle(char *dst, const char *src, unsigned long n) {
    leaf(dst, src, n);
}
void entry(const char *src) {
    char buf[16];
    middle(buf, src, 12);
}
"""
    assert _scan(code) == []


def test_conflicting_callers_remain_conservative():
    code = r"""
void memcpy(void *dst, const void *src, unsigned long n);

void leaf(char *dst, const char *src, unsigned long n) {
    memcpy(dst, src, n);
}
void safe_entry(const char *src) {
    char buf[8];
    leaf(buf, src, 4);
}
void unsafe_entry(const char *src) {
    char buf[8];
    leaf(buf, src, 12);
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].engine == "Interprocedural"
    assert "do not prove the copy safe" in issues[0].message
    assert issues[0].confidence == Confidence.LIMITED
