"""
Unit tests for MemcpyStructMemberOverflowRule (CGULL-044).
"""

from cgull.engine import CGullScanner
from cgull.models import Severity
from cgull.rules.memory_management import MemcpyStructMemberOverflowRule


STRUCT_MEMCPY_TEST_CODE = """
#include <string.h>

struct Inner {
    char inner_buf[50];
};

struct A {
    char array_a[100];
    struct Inner in;
};

/* Struct member destination with constant n */
void fun_c_overflow(struct A *a, const char *src) {
    memcpy(a->array_a, src, 150);
}

void fun_c_safe(struct A *a, const char *src) {
    memcpy(a->array_a, src, 50);
}

/* Struct member destination with variable n */
void fun_c_var_ungated(struct A *a, const char *src, int n) {
    memcpy(a->array_a, src, n);
}

void fun_c_var_gated(struct A *a, const char *src, int n) {
    if (n <= 100) {
        memcpy(a->array_a, src, n);
    }
}

void fun_c_var_gated_bad(struct A *a, const char *src, int n) {
    if (n <= 150) {
        memcpy(a->array_a, src, n);
    }
}

/* Plain local array destination */
void fun_plain_overflow(const char *src) {
    char buf[100];
    memcpy(buf, src, 120);
}

void fun_plain_safe(const char *src) {
    char buf[100];
    memcpy(buf, src, 80);
}

void fun_plain_var_ungated(const char *src, int n) {
    char buf[100];
    memcpy(buf, src, n);
}

void fun_plain_var_gated(const char *src, int n) {
    char buf[100];
    if (n <= 100) {
        memcpy(buf, src, n);
    }
}

/* memmove and memset */
void fun_memmove_overflow(struct A *a, const char *src) {
    memmove(a->array_a, src, 200);
}

void fun_memset_overflow(struct A *a) {
    memset(a->in.inner_buf, 0, 60);
}

void fun_memset_safe(struct A *a) {
    memset(a->in.inner_buf, 0, 50);
}

/* sizeof(...) size argument */
struct Small {
    char data[20];
};

struct Big {
    char data[100];
};

void fun_sizeof_overflow(struct Small *s, struct Big *b) {
    memcpy(s->data, b->data, sizeof(struct Big));
}

void fun_sizeof_safe(struct Small *s, struct Big *b) {
    memcpy(b->data, s->data, sizeof(struct Small));
}
"""


def test_memcpy_struct_member_and_plain_array_overflow():
    scanner = CGullScanner(rules=[MemcpyStructMemberOverflowRule()])
    res = scanner.scan_text(STRUCT_MEMCPY_TEST_CODE, file_path="test_memcpy.c")

    issues_by_line = {issue.line_number: issue for issue in res.issues}

    # Line 15: fun_c_overflow -> memcpy 150 bytes into 100-byte a->array_a (flagged)
    assert 15 in issues_by_line
    assert issues_by_line[15].impact == Severity.HIGH
    assert "provably exceeds destination buffer capacity" in issues_by_line[15].message

    # Line 19: fun_c_safe -> memcpy 50 bytes into 100-byte a->array_a (not flagged)
    assert 19 not in issues_by_line

    # Line 24: fun_c_var_ungated -> memcpy n bytes into 100-byte a->array_a without gate (flagged)
    assert 24 in issues_by_line
    assert "variable size argument 'n' is not gated" in issues_by_line[24].message

    # Line 29: fun_c_var_gated -> if (n <= 100) memcpy(a->array_a, src, n) (not flagged)
    assert 29 not in issues_by_line

    # Line 35: fun_c_var_gated_bad -> if (n <= 150) memcpy(a->array_a, src, n) (flagged because gate 150 > cap 100)
    assert 35 in issues_by_line

    # Line 42: fun_plain_overflow -> memcpy 120 into 100-byte local buf (flagged)
    assert 42 in issues_by_line

    # Line 47: fun_plain_safe -> memcpy 80 into 100-byte local buf (not flagged)
    assert 47 not in issues_by_line

    # Line 52: fun_plain_var_ungated -> ungated n into local buf (flagged)
    assert 52 in issues_by_line

    # Line 58: fun_plain_var_gated -> gated n <= 100 into local buf (not flagged)
    assert 58 not in issues_by_line

    # Line 64: fun_memmove_overflow -> memmove 200 into 100-byte a->array_a (flagged)
    assert 64 in issues_by_line

    # Line 68: fun_memset_overflow -> memset 60 into 50-byte a->in.inner_buf (flagged)
    assert 68 in issues_by_line

    # Line 72: fun_memset_safe -> memset 50 into 50-byte a->in.inner_buf (not flagged)
    assert 72 not in issues_by_line

    # Line 85: fun_sizeof_overflow -> memcpy sizeof(struct Big) [100] into s->data [20] (flagged)
    assert 85 in issues_by_line

    # Line 89: fun_sizeof_safe -> memcpy sizeof(struct Small) [20] into b->data [100] (not flagged)
    assert 89 not in issues_by_line
