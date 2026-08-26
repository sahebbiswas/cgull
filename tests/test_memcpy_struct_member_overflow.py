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
    int int_arr[10];  /* 10 ints = 40 bytes capacity */
    struct Inner in;
};

/* Struct member destination with constant n */
void fun_c_overflow(struct A *a, const char *src) {
    memcpy(a->array_a, src, 150);
}

void fun_c_safe(struct A *a, const char *src) {
    memcpy(a->array_a, src, 50);
}

/* Non-byte array destination */
void fun_non_byte_safe(struct A *a, const int *src) {
    memcpy(a->int_arr, src, 40);  /* 40 bytes <= 40 bytes capacity (10 ints) */
}

void fun_non_byte_overflow(struct A *a, const int *src) {
    memcpy(a->int_arr, src, 50);  /* 50 bytes > 40 bytes capacity (10 ints) */
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

/* CFG Path Dominance: check inside if block, call outside */
void fun_cfg_outside_if(struct A *a, const char *src, int n) {
    if (n <= 100) {
        /* check only controls inside block */
    }
    memcpy(a->array_a, src, n);
}

/* CFG Reassignment: variable reassigned after check */
void fun_cfg_reassigned(struct A *a, const char *src, int n) {
    if (n <= 100) {
        n = 150;
        memcpy(a->array_a, src, n);
    }
}

/* Symbolic limit: unconstrained parameter limit vs proven macro limit */
void fun_symbolic_unproven(struct A *a, const char *src, int n, int max_len) {
    if (n <= max_len) {
        memcpy(a->array_a, src, n);
    }
}

#define SAFE_MAX 80
void fun_symbolic_proven(struct A *a, const char *src, int n) {
    if (n <= SAFE_MAX) {
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
    int extra[10];
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

    # Line 16: fun_c_overflow -> memcpy 150 bytes into 100-byte a->array_a (flagged)
    assert 16 in issues_by_line
    assert issues_by_line[16].impact == Severity.HIGH
    assert "provably exceeds destination buffer capacity" in issues_by_line[16].message

    # Line 20: fun_c_safe -> memcpy 50 bytes into 100-byte a->array_a (not flagged)
    assert 20 not in issues_by_line

    # Line 25: fun_non_byte_safe -> 40 bytes into int_arr[10] (40 bytes capacity) (not flagged)
    assert 25 not in issues_by_line

    # Line 29: fun_non_byte_overflow -> 50 bytes into int_arr[10] (40 bytes capacity) (flagged)
    assert 29 in issues_by_line
    assert "50 bytes" in issues_by_line[29].message
    assert "40 bytes" in issues_by_line[29].message

    # Line 34: fun_c_var_ungated -> memcpy n bytes into 100-byte a->array_a without gate (flagged)
    assert 34 in issues_by_line
    assert "variable size argument 'n' is not gated" in issues_by_line[34].message

    # Line 39: fun_c_var_gated -> if (n <= 100) memcpy(a->array_a, src, n) (not flagged)
    assert 39 not in issues_by_line

    # Line 45: fun_c_var_gated_bad -> if (n <= 150) memcpy(a->array_a, src, n) (flagged because gate 150 > cap 100)
    assert 45 in issues_by_line

    # Line 54: fun_cfg_outside_if -> check inside if block, call outside (flagged)
    assert 54 in issues_by_line

    # Line 61: fun_cfg_reassigned -> n reassigned to 150 inside block (flagged)
    assert 61 in issues_by_line

    # Line 68: fun_symbolic_unproven -> gated by unconstrained parameter max_len (flagged)
    assert 68 in issues_by_line

    # Line 75: fun_symbolic_proven -> gated by #define SAFE_MAX 80 <= 100 (not flagged)
    assert 75 not in issues_by_line

    # Line 82: fun_plain_overflow -> memcpy 120 into 100-byte local buf (flagged)
    assert 82 in issues_by_line

    # Line 87: fun_plain_safe -> memcpy 80 into 100-byte local buf (not flagged)
    assert 87 not in issues_by_line

    # Line 92: fun_plain_var_ungated -> ungated n into local buf (flagged)
    assert 92 in issues_by_line

    # Line 98: fun_plain_var_gated -> gated n <= 100 into local buf (not flagged)
    assert 98 not in issues_by_line

    # Line 104: fun_memmove_overflow -> memmove 200 into 100-byte a->array_a (flagged)
    assert 104 in issues_by_line

    # Line 108: fun_memset_overflow -> memset 60 into 50-byte a->in.inner_buf (flagged)
    assert 108 in issues_by_line

    # Line 112: fun_memset_safe -> memset 50 into 50-byte a->in.inner_buf (not flagged)
    assert 112 not in issues_by_line

    # Line 126: fun_sizeof_overflow -> memcpy sizeof(struct Big) into s->data [20] (flagged)
    assert 126 in issues_by_line

    # Line 130: fun_sizeof_safe -> memcpy sizeof(struct Small) [20] into b->data [100] (not flagged)
    assert 130 not in issues_by_line
