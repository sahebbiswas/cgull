"""
Unit tests for MemcpyStructMemberOverflowRule (CGULL-044).
"""

from cgull.engine import CGullScanner
from cgull.models import Severity, AnalysisEngine
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

/* Struct member destination with variable n (unsigned vs signed) */
void fun_c_var_ungated(struct A *a, const char *src, size_t n) {
    memcpy(a->array_a, src, n);
}

void fun_c_var_gated_unsigned(struct A *a, const char *src, size_t n) {
    if (n <= 100) {
        memcpy(a->array_a, src, n);
    }
}

void fun_signed_no_lower(struct A *a, const char *src, int n) {
    if (n <= 100) {
        memcpy(a->array_a, src, n);  /* Signed n lacks non-negative check -> flagged */
    }
}

void fun_signed_gated(struct A *a, const char *src, int n) {
    if (n >= 0 && n <= 100) {
        memcpy(a->array_a, src, n);  /* Signed n with both lower and upper checks -> safe */
    }
}

void fun_signed_gated_alt(struct A *a, const char *src, int n) {
    if (0 <= n && 100 >= n) {
        memcpy(a->array_a, src, n);  /* Inverted expression syntax -> safe */
    }
}

void fun_signed_early_return(struct A *a, const char *src, int n) {
    if (n < 0 || n > 100) return;
    memcpy(a->array_a, src, n);  /* Early return on invalid n -> safe */
}

void fun_c_var_gated_bad(struct A *a, const char *src, size_t n) {
    if (n <= 150) {
        memcpy(a->array_a, src, n);
    }
}

/* CFG Path Dominance: check inside if block, call outside */
void fun_cfg_outside_if(struct A *a, const char *src, size_t n) {
    if (n <= 100) {
        /* check only controls inside block */
    }
    memcpy(a->array_a, src, n);
}

/* CFG Reassignment: variable reassigned after check */
void fun_cfg_reassigned(struct A *a, const char *src, size_t n) {
    if (n <= 100) {
        n = 150;
        memcpy(a->array_a, src, n);
    }
}

/* Symbolic limit: unconstrained parameter limit vs proven macro limit */
void fun_symbolic_unproven(struct A *a, const char *src, size_t n, size_t max_len) {
    if (n <= max_len) {
        memcpy(a->array_a, src, n);
    }
}

#define SAFE_MAX 80
void fun_symbolic_proven(struct A *a, const char *src, size_t n) {
    if (n <= SAFE_MAX - 10) {
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

void fun_plain_var_ungated(const char *src, size_t n) {
    char buf[100];
    memcpy(buf, src, n);
}

void fun_plain_var_gated(const char *src, size_t n) {
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

/* sizeof(...) arithmetic expressions */
void fun_sizeof_arithmetic_safe(char *src) {
    int buf[10];  /* 40 bytes capacity */
    memcpy(buf, src, (1 << 2) * 10);  /* 40 <= 40 -> safe */
}

void fun_sizeof_arithmetic_overflow(char *src) {
    int buf[10];  /* 40 bytes capacity */
    memcpy(buf, src, 11 * sizeof(int));  /* 44 > 40 -> overflow */
}

/* Multiline call argument extraction */
void fun_multiline_call(struct A *a, const char *src) {
    memcpy(
        a->array_a,
        src,
        150
    );
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

    # Line 34: fun_c_var_ungated -> memcpy n bytes into 100-byte a->array_a without gate (flagged)
    assert 34 in issues_by_line

    # Line 39: fun_c_var_gated_unsigned -> if (n <= 100) memcpy(a->array_a, src, n) for size_t (not flagged)
    assert 39 not in issues_by_line

    # Line 45: fun_signed_no_lower -> if (n <= 100) for signed int n (lacks n >= 0) -> (flagged)
    assert 45 in issues_by_line

    # Line 51: fun_signed_gated -> if (n >= 0 && n <= 100) for signed int n -> (not flagged)
    assert 51 not in issues_by_line

    # Line 57: fun_signed_gated_alt -> if (0 <= n && 100 >= n) -> (not flagged)
    assert 57 not in issues_by_line

    # Line 62: fun_signed_early_return -> early return -> (not flagged)
    assert 62 not in issues_by_line

    # Line 68: fun_c_var_gated_bad -> if (n <= 150) memcpy(a->array_a, src, n) (flagged)
    assert 68 in issues_by_line

    # Line 77: fun_cfg_outside_if -> check inside if block, call outside (flagged)
    assert 77 in issues_by_line

    # Line 84: fun_cfg_reassigned -> n reassigned to 150 inside block (flagged)
    assert 84 in issues_by_line

    # Line 91: fun_symbolic_unproven -> gated by unconstrained parameter max_len (flagged)
    assert 91 in issues_by_line

    # Line 98: fun_symbolic_proven -> gated by #define SAFE_MAX 80 - 10 <= 100 (not flagged)
    assert 98 not in issues_by_line

    # Line 105: fun_plain_overflow -> memcpy 120 into 100-byte local buf (flagged)
    assert 105 in issues_by_line

    # Line 110: fun_plain_safe -> memcpy 80 into 100-byte local buf (not flagged)
    assert 110 not in issues_by_line

    # Line 115: fun_plain_var_ungated -> ungated n into local buf (flagged)
    assert 115 in issues_by_line

    # Line 121: fun_plain_var_gated -> gated n <= 100 into local buf (not flagged)
    assert 121 not in issues_by_line

    # Line 127: fun_memmove_overflow -> memmove 200 into 100-byte a->array_a (flagged)
    assert 127 in issues_by_line

    # Line 131: fun_memset_overflow -> memset 60 into 50-byte a->in.inner_buf (flagged)
    assert 131 in issues_by_line

    # Line 135: fun_memset_safe -> memset 50 into 50-byte a->in.inner_buf (not flagged)
    assert 135 not in issues_by_line

    # Line 141: fun_sizeof_arithmetic_safe -> (1 << 2) * 10 [40] into buf[10] (40 bytes) (not flagged)
    assert 141 not in issues_by_line

    # Line 146: fun_sizeof_arithmetic_overflow -> 11 * sizeof(int) [44] into buf[10] (40 bytes) (flagged)
    assert 146 in issues_by_line

    # Line 151: fun_multiline_call -> multiline memcpy 150 bytes into 100-byte array_a (flagged)
    assert 151 in issues_by_line


def test_memcpy_scan_line_regex_mode():
    scanner = CGullScanner(rules=[MemcpyStructMemberOverflowRule()], engine_mode=AnalysisEngine.REGEX)
    res = scanner.scan_text(STRUCT_MEMCPY_TEST_CODE, file_path="test_memcpy_regex.c")
    issues_by_line = {issue.line_number: issue for issue in res.issues}
    assert 105 in issues_by_line
    assert "120 bytes" in issues_by_line[105].message
