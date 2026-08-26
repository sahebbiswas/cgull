"""
Cross-cutting variant regression matrix test.

Consolidated test fixture and CI check exercising every variant V1-V7, plus union
and multi-level-typedef edge cases against all consuming rules:
- CGULL-007 (ArrayIndexOutOfBoundsRule)
- CGULL-001 / CGULL-037 (BannedFunctionsRule / StrncpyNullTerminationRule)
- CGULL-044 (MemcpyStructMemberOverflowRule)
"""

from cgull.ast_analyzer import CASTParser
from cgull.engine import CGullScanner
from cgull.models import Severity
from cgull.rules.types_and_arrays import ArrayIndexOutOfBoundsRule
from cgull.rules.banned_functions import BannedFunctionsRule, StrncpyNullTerminationRule
from cgull.rules.memory_management import MemcpyStructMemberOverflowRule


MATRIX_TEST_CODE = r"""
#include <string.h>

struct Inner {
    char inner_buf[50];
};

struct A {
    char array_a[100];
    struct Inner in;
    struct Inner *in_ptr;
};

typedef struct A A_t;
typedef A_t A_t_level2;
typedef A_t_level2 *A_ptr_level3;

union DataUnion {
    char buf[60];
    int int_val;
};

typedef union DataUnion Union_t;
typedef Union_t Union_t_level2;

/* =========================================================================
   CGULL-007: Array Index Out of Bounds (V1-V7, Union, Multi-level typedef)
   ========================================================================= */

/* V1: direct pointer, single level */
void cgull_007_v1_good(struct A *a, int i) {
    if (i >= 0 && i < 100) {
        a->array_a[i] = 'x';
    }
}
void cgull_007_v1_bad(struct A *a, int i) {
    if (i >= 0 && i < 200) {
        a->array_a[i] = 'x';
    }
}

/* V2: by-value struct, single level */
void cgull_007_v2_good(struct A a_val, int i) {
    if (i >= 0 && i < 100) {
        a_val.array_a[i] = 'x';
    }
}
void cgull_007_v2_bad(struct A a_val, int i) {
    if (i >= 0 && i < 200) {
        a_val.array_a[i] = 'x';
    }
}

/* V3: pointer -> nested-by-value member */
void cgull_007_v3_good(struct A *a, int i) {
    if (i >= 0 && i < 50) {
        a->in.inner_buf[i] = 'x';
    }
}
void cgull_007_v3_bad(struct A *a, int i) {
    if (i >= 0 && i < 200) {
        a->in.inner_buf[i] = 'x';
    }
}

/* V4: pointer -> nested-pointer member */
void cgull_007_v4_good(struct A *a, int i) {
    if (i >= 0 && i < 50) {
        a->in_ptr->inner_buf[i] = 'x';
    }
}
void cgull_007_v4_bad(struct A *a, int i) {
    if (i >= 0 && i < 200) {
        a->in_ptr->inner_buf[i] = 'x';
    }
}

/* V5: array-of-structs, indexed instance */
void cgull_007_v5_good(struct A arr[10], int i) {
    if (i >= 0 && i < 100) {
        arr[0].array_a[i] = 'x';
    }
}
void cgull_007_v5_bad(struct A arr[10], int i) {
    if (i >= 0 && i < 200) {
        arr[0].array_a[i] = 'x';
    }
}

/* V6: array-of-struct-pointers */
void cgull_007_v6_good(struct A *parr[10], int i) {
    if (i >= 0 && i < 100) {
        parr[0]->array_a[i] = 'x';
    }
}
void cgull_007_v6_bad(struct A *parr[10], int i) {
    if (i >= 0 && i < 200) {
        parr[0]->array_a[i] = 'x';
    }
}

/* V7: typedef indirection */
void cgull_007_v7_good(A_t *b, int i) {
    if (i >= 0 && i < 100) {
        b->array_a[i] = 'x';
    }
}
void cgull_007_v7_bad(A_t *b, int i) {
    if (i >= 0 && i < 200) {
        b->array_a[i] = 'x';
    }
}

/* Union member edge case */
void cgull_007_union_good(Union_t_level2 *u, int i) {
    if (i >= 0 && i < 60) {
        u->buf[i] = 'x';
    }
}
void cgull_007_union_bad(Union_t_level2 *u, int i) {
    if (i >= 0 && i < 200) {
        u->buf[i] = 'x';
    }
}

/* Multi-level typedef edge case */
void cgull_007_multilevel_good(A_ptr_level3 c, int i) {
    if (i >= 0 && i < 100) {
        c->array_a[i] = 'x';
    }
}
void cgull_007_multilevel_bad(A_ptr_level3 c, int i) {
    if (i >= 0 && i < 200) {
        c->array_a[i] = 'x';
    }
}

/* =========================================================================
   CGULL-001 / CGULL-037: Banned Functions & strncpy (V1-V7, Union, Multi-level typedef)
   ========================================================================= */

/* V1: direct pointer */
void banned_strcpy_v1_good(struct A *a) {
    strcpy(a->array_a, "short string");
}
void banned_strcpy_v1_bad(struct A *a) {
    strcpy(a->array_a, "This string literal is way too long and definitely exceeds the one hundred byte capacity of the array_a field in struct A!");
}

/* V2: by-value struct */
void banned_strcpy_v2_good(struct A a_val) {
    strcpy(a_val.array_a, "short string");
}
void banned_strcpy_v2_bad(struct A a_val) {
    strcpy(a_val.array_a, "This string literal is way too long and definitely exceeds the one hundred byte capacity of the array_a field in struct A!");
}

/* V3: pointer -> nested-by-value member */
void banned_strcpy_v3_good(struct A *a) {
    strcpy(a->in.inner_buf, "short string");
}
void banned_strcpy_v3_bad(struct A *a) {
    strcpy(a->in.inner_buf, "This literal is definitely much longer than fifty bytes total!");
}

/* V4: pointer -> nested-pointer member */
void banned_strcpy_v4_good(struct A *a) {
    strcpy(a->in_ptr->inner_buf, "short string");
}
void banned_strcpy_v4_bad(struct A *a) {
    strcpy(a->in_ptr->inner_buf, "This literal is definitely much longer than fifty bytes total!");
}

/* V5: array-of-structs */
void banned_strcpy_v5_good(struct A arr[10]) {
    strcpy(arr[0].array_a, "short string");
}
void banned_strcpy_v5_bad(struct A arr[10]) {
    strcpy(arr[0].array_a, "This string literal is way too long and definitely exceeds the one hundred byte capacity of the array_a field in struct A!");
}

/* V6: array-of-struct-pointers */
void banned_strcpy_v6_good(struct A *parr[10]) {
    strcpy(parr[0]->array_a, "short string");
}
void banned_strcpy_v6_bad(struct A *parr[10]) {
    strcpy(parr[0]->array_a, "This string literal is way too long and definitely exceeds the one hundred byte capacity of the array_a field in struct A!");
}

/* V7: typedef indirection */
void banned_strcpy_v7_good(A_t *b) {
    strcpy(b->array_a, "short string");
}
void banned_strcpy_v7_bad(A_t *b) {
    strcpy(b->array_a, "This string literal is way too long and definitely exceeds the one hundred byte capacity of the array_a field in struct A!");
}

/* Union member edge case */
void banned_strcpy_union_good(Union_t_level2 *u) {
    strcpy(u->buf, "short");
}
void banned_strcpy_union_bad(Union_t_level2 *u) {
    strcpy(u->buf, "This string literal is way too long and definitely exceeds the sixty byte capacity of the buf field in DataUnion!");
}

/* Multi-level typedef edge case */
void banned_strcpy_multilevel_good(A_ptr_level3 c) {
    strcpy(c->array_a, "short string");
}
void banned_strcpy_multilevel_bad(A_ptr_level3 c) {
    strcpy(c->array_a, "This string literal is way too long and definitely exceeds the one hundred byte capacity of the array_a field in struct A!");
}

/* strncpy null termination (CGULL-037) */
void strncpy_v1_good(const char *src) {
    char buf[100];
    strncpy(buf, src, 100);
    buf[99] = '\0';
}
void strncpy_v1_bad(const char *src) {
    char buf[100];
    strncpy(buf, src, 100);
}

/* =========================================================================
   CGULL-044: Memcpy Struct Member Overflow (V1-V7, Union, Multi-level typedef)
   ========================================================================= */

/* V1: direct pointer */
void memcpy_v1_good(struct A *a, const char *src) {
    memcpy(a->array_a, src, 50);
}
void memcpy_v1_bad(struct A *a, const char *src) {
    memcpy(a->array_a, src, 150);
}

/* V2: by-value struct */
void memcpy_v2_good(struct A a_val, const char *src) {
    memcpy(a_val.array_a, src, 50);
}
void memcpy_v2_bad(struct A a_val, const char *src) {
    memcpy(a_val.array_a, src, 150);
}

/* V3: pointer -> nested-by-value member */
void memcpy_v3_good(struct A *a, const char *src) {
    memcpy(a->in.inner_buf, src, 30);
}
void memcpy_v3_bad(struct A *a, const char *src) {
    memcpy(a->in.inner_buf, src, 80);
}

/* V4: pointer -> nested-pointer member */
void memcpy_v4_good(struct A *a, const char *src) {
    memcpy(a->in_ptr->inner_buf, src, 30);
}
void memcpy_v4_bad(struct A *a, const char *src) {
    memcpy(a->in_ptr->inner_buf, src, 80);
}

/* V5: array-of-structs */
void memcpy_v5_good(struct A arr[10], const char *src) {
    memcpy(arr[0].array_a, src, 50);
}
void memcpy_v5_bad(struct A arr[10], const char *src) {
    memcpy(arr[0].array_a, src, 150);
}

/* V6: array-of-struct-pointers */
void memcpy_v6_good(struct A *parr[10], const char *src) {
    memcpy(parr[0]->array_a, src, 50);
}
void memcpy_v6_bad(struct A *parr[10], const char *src) {
    memcpy(parr[0]->array_a, src, 150);
}

/* V7: typedef indirection */
void memcpy_v7_good(A_t *b, const char *src) {
    memcpy(b->array_a, src, 50);
}
void memcpy_v7_bad(A_t *b, const char *src) {
    memcpy(b->array_a, src, 150);
}

/* Union member edge case */
void memcpy_union_good(Union_t_level2 *u, const char *src) {
    memcpy(u->buf, src, 40);
}
void memcpy_union_bad(Union_t_level2 *u, const char *src) {
    memcpy(u->buf, src, 100);
}

/* Multi-level typedef edge case */
void memcpy_multilevel_good(A_ptr_level3 c, const char *src) {
    memcpy(c->array_a, src, 50);
}
void memcpy_multilevel_bad(A_ptr_level3 c, const char *src) {
    memcpy(c->array_a, src, 150);
}
"""


def _get_issues_by_function(scanner, code, file_path="matrix_test.c"):
    res = scanner.scan_text(code, file_path=file_path)
    ctx = CASTParser().parse(code)
    fn_issues = {}
    for issue in res.issues:
        for fn in ctx.functions:
            if fn.start_line <= issue.line_number <= fn.end_line:
                fn_issues.setdefault(fn.name, []).append(issue)
                break
    return res, fn_issues


def test_cross_cutting_cgull_007_variants():
    scanner = CGullScanner(rules=[ArrayIndexOutOfBoundsRule()])
    res, fn_issues = _get_issues_by_function(scanner, MATRIX_TEST_CODE)

    expected_bads = [
        "cgull_007_v1_bad", "cgull_007_v2_bad", "cgull_007_v3_bad", "cgull_007_v4_bad",
        "cgull_007_v5_bad", "cgull_007_v6_bad", "cgull_007_v7_bad",
        "cgull_007_union_bad", "cgull_007_multilevel_bad"
    ]
    expected_goods = [
        "cgull_007_v1_good", "cgull_007_v2_good", "cgull_007_v3_good", "cgull_007_v4_good",
        "cgull_007_v5_good", "cgull_007_v6_good", "cgull_007_v7_good",
        "cgull_007_union_good", "cgull_007_multilevel_good"
    ]

    for bad_fn in expected_bads:
        assert bad_fn in fn_issues, f"Expected CGULL-007 finding in {bad_fn}"
        assert len(fn_issues[bad_fn]) == 1
        assert fn_issues[bad_fn][0].rule_id == "CGULL-007"

    for good_fn in expected_goods:
        assert good_fn not in fn_issues, f"Unexpected CGULL-007 finding in {good_fn}"

    assert len(res.issues) == len(expected_bads)


def test_cross_cutting_banned_strcpy_and_strncpy_variants():
    scanner = CGullScanner(rules=[BannedFunctionsRule(), StrncpyNullTerminationRule()])
    res, fn_issues = _get_issues_by_function(scanner, MATRIX_TEST_CODE)

    banned_bad_fns = [
        "banned_strcpy_v1_bad", "banned_strcpy_v2_bad", "banned_strcpy_v3_bad",
        "banned_strcpy_v4_bad", "banned_strcpy_v5_bad", "banned_strcpy_v6_bad",
        "banned_strcpy_v7_bad", "banned_strcpy_union_bad", "banned_strcpy_multilevel_bad"
    ]
    banned_good_fns = [
        "banned_strcpy_v1_good", "banned_strcpy_v2_good", "banned_strcpy_v3_good",
        "banned_strcpy_v4_good", "banned_strcpy_v5_good", "banned_strcpy_v6_good",
        "banned_strcpy_v7_good", "banned_strcpy_union_good", "banned_strcpy_multilevel_good"
    ]

    for bad_fn in banned_bad_fns:
        assert bad_fn in fn_issues, f"Expected issue in {bad_fn}"
        issues = fn_issues[bad_fn]
        assert len(issues) == 1
        assert issues[0].impact == Severity.HIGH
        assert "exceeds destination buffer size" in issues[0].message or "Buffer Overflow" in issues[0].message

    for good_fn in banned_good_fns:
        assert good_fn in fn_issues, f"Expected fragile issue in {good_fn}"
        issues = fn_issues[good_fn]
        assert len(issues) == 1
        assert issues[0].impact == Severity.LOW
        assert "provably shorter than destination buffer size" in issues[0].message

    # Strncpy tests
    assert "strncpy_v1_good" not in fn_issues
    assert "strncpy_v1_bad" in fn_issues
    assert len(fn_issues["strncpy_v1_bad"]) == 1
    assert fn_issues["strncpy_v1_bad"][0].rule_id == "CGULL-037"


def test_cross_cutting_memcpy_variants():
    scanner = CGullScanner(rules=[MemcpyStructMemberOverflowRule()])
    res, fn_issues = _get_issues_by_function(scanner, MATRIX_TEST_CODE)

    memcpy_bad_fns = [
        "memcpy_v1_bad", "memcpy_v2_bad", "memcpy_v3_bad", "memcpy_v4_bad",
        "memcpy_v5_bad", "memcpy_v6_bad", "memcpy_v7_bad",
        "memcpy_union_bad", "memcpy_multilevel_bad"
    ]
    memcpy_good_fns = [
        "memcpy_v1_good", "memcpy_v2_good", "memcpy_v3_good", "memcpy_v4_good",
        "memcpy_v5_good", "memcpy_v6_good", "memcpy_v7_good",
        "memcpy_union_good", "memcpy_multilevel_good"
    ]

    for bad_fn in memcpy_bad_fns:
        assert bad_fn in fn_issues, f"Expected CGULL-044 issue in {bad_fn}"
        issues = fn_issues[bad_fn]
        assert len(issues) == 1
        assert issues[0].rule_id == "CGULL-044"
        assert issues[0].impact == Severity.HIGH

    for good_fn in memcpy_good_fns:
        assert good_fn not in fn_issues, f"Unexpected CGULL-044 issue in {good_fn}"

    assert len(res.issues) == len(memcpy_bad_fns)


def test_cross_cutting_all_rules_combined():
    scanner = CGullScanner(rules=[
        ArrayIndexOutOfBoundsRule(),
        BannedFunctionsRule(),
        StrncpyNullTerminationRule(),
        MemcpyStructMemberOverflowRule()
    ])
    res, _ = _get_issues_by_function(scanner, MATRIX_TEST_CODE)

    # Assert exact deterministic total finding counts across rules:
    # CGULL-007: 9 bad functions -> 9 findings
    # CGULL-001: 9 bad (HIGH) + 9 good (LOW) -> 18 findings
    # CGULL-037: 1 bad -> 1 finding
    # CGULL-044: 9 bad -> 9 findings
    # Total expected findings = 9 + 18 + 1 + 9 = 37 findings
    assert len(res.issues) == 37, f"Expected 37 total issues, got {len(res.issues)}"
