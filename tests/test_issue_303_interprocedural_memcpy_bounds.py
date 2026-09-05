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


def test_local_cfg_safety_proof_is_not_overridden_by_unknown_size_fact():
    code = r"""
void memcpy(void *dst, const void *src, unsigned long n);

void local_copy(const char *src, unsigned long n) {
    char buf[8];
    if (n <= 8) {
        memcpy(buf, src, n);
    }
}
"""
    assert _scan(code) == []


def test_same_line_safe_copy_does_not_suppress_other_destination_overflow():
    code = r"""
void memcpy(void *dst, const void *src, unsigned long n);

void sibling_copies(const char *src) {
    char large[16];
    char small[4];
    memcpy(large, src, 4); memcpy(&small[2], src, 4);
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert "small[2]" in issues[0].message
    assert "provably exceeds destination buffer capacity" in issues[0].message


def test_multiline_safe_wrapper_call_suppresses_legacy_finding():
    code = r"""
void memcpy(void *dst, const void *src, unsigned long n);

void leaf(char *dst, const char *src, unsigned long n) {
    memcpy(
        dst,
        src,
        n
    );
}
void entry(const char *src) {
    char buf[16];
    leaf(buf, src, 8);
}
"""
    assert _scan(code) == []


def test_multiline_unsafe_wrapper_call_is_reported_once():
    code = r"""
void memcpy(void *dst, const void *src, unsigned long n);

void leaf(char *dst, const char *src, unsigned long n) {
    memcpy(
        dst,
        src,
        n
    );
}
void entry(const char *src) {
    char buf[4];
    leaf(buf, src, 8);
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].engine == "Interprocedural"
    assert "Provable out-of-bounds write" in issues[0].message


def test_safe_struct_member_with_digit_is_suppressed():
    code = r"""
void memcpy(void *dst, const void *src, unsigned long n);

struct Packet {
    char field1[16];
};

void copy(struct Packet *packet, const char *src) {
    memcpy(packet->field1, src, 8);
}
"""
    assert _scan(code) == []


def test_interprocedural_issue_uses_original_source_line():
    code = r"""
void memcpy(void *dst, const void *src, unsigned long n);

void leaf(char *dst, const char *src, unsigned long n) {
    memcpy(dst, src, n);
}
void entry(const char *src) {
    char buf[4];
    leaf(buf, src, 8);
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].line_number == 5
