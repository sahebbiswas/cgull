"""
Unit tests for CGULL-007 (Array Index Out of Bounds) struct member array capacity resolution.
"""

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import ArrayIndexOutOfBoundsRule


def test_canonical_repro_cgull_007():
    code = """
    struct A { char array_a[100]; };
    void fun_a(struct A *a, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            if (i >= 0 && i < 500) {   /* wrong bound: real capacity is 100 */
                a->array_a[i] = src[i];
            }
        }
    }
    """
    ctx = CASTParser().parse(code)
    rule = ArrayIndexOutOfBoundsRule()
    issues = rule.scan_ast("test.c", ctx)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-007"
    assert "array_a" in issues[0].message


def test_struct_member_variants_v1_to_v7():
    code = """
    struct Inner { char inner_buf[50]; };
    struct A {
        char array_a[100];
        struct Inner in;
        struct Inner *in_ptr;
    };
    typedef struct A A_t;

    /* V1: direct pointer, single level */
    void fun_v1_bad(struct A *a, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            a->array_a[i] = src[i];
        }
    }
    void fun_v1_good(struct A *a, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            if (i >= 0 && i < 100) {
                a->array_a[i] = src[i];
            }
        }
    }

    /* V2: by-value struct, single level */
    void fun_v2_bad(struct A a_val, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            a_val.array_a[i] = src[i];
        }
    }
    void fun_v2_good(struct A a_val, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            if (i >= 0 && i < 100) {
                a_val.array_a[i] = src[i];
            }
        }
    }

    /* V3: pointer -> nested-by-value member */
    void fun_v3_bad(struct A *a, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            a->in.inner_buf[i] = src[i];
        }
    }
    void fun_v3_good(struct A *a, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            if (i >= 0 && i < 50) {
                a->in.inner_buf[i] = src[i];
            }
        }
    }

    /* V4: pointer -> nested-pointer member */
    void fun_v4_bad(struct A *a, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            a->in_ptr->inner_buf[i] = src[i];
        }
    }
    void fun_v4_good(struct A *a, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            if (i >= 0 && i < 50) {
                a->in_ptr->inner_buf[i] = src[i];
            }
        }
    }

    /* V5: array-of-structs, indexed instance */
    void fun_v5_bad(struct A arr[10], const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            arr[0].array_a[i] = src[i];
        }
    }
    void fun_v5_good(struct A arr[10], const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            if (i >= 0 && i < 100) {
                arr[0].array_a[i] = src[i];
            }
        }
    }

    /* V6: array-of-struct-pointers */
    void fun_v6_bad(struct A *parr[10], const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            parr[0]->array_a[i] = src[i];
        }
    }
    void fun_v6_good(struct A *parr[10], const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            if (i >= 0 && i < 100) {
                parr[0]->array_a[i] = src[i];
            }
        }
    }

    /* V7: typedef indirection */
    void fun_v7_bad(A_t *b, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            b->array_a[i] = src[i];
        }
    }
    void fun_v7_good(A_t *b, const char *src, int len) {
        int i;
        for (i = 0; i < len; i++) {
            if (i >= 0 && i < 100) {
                b->array_a[i] = src[i];
            }
        }
    }
    """
    ctx = CASTParser().parse(code)
    rule = ArrayIndexOutOfBoundsRule()
    issues = rule.scan_ast("test.c", ctx)

    reported_fn_names = set()
    for issue in issues:
        for fn in ctx.functions:
            if fn.start_line <= issue.line_number <= fn.end_line:
                reported_fn_names.add(fn.name)

    # All bad functions should be flagged
    expected_bad = {
        "fun_v1_bad", "fun_v2_bad", "fun_v3_bad", "fun_v4_bad",
        "fun_v5_bad", "fun_v6_bad", "fun_v7_bad"
    }
    for bad_fn in expected_bad:
        assert bad_fn in reported_fn_names, f"Expected issue in {bad_fn}"

    # None of the good functions should be flagged
    expected_good = {
        "fun_v1_good", "fun_v2_good", "fun_v3_good", "fun_v4_good",
        "fun_v5_good", "fun_v6_good", "fun_v7_good"
    }
    for good_fn in expected_good:
        assert good_fn not in reported_fn_names, f"Unexpected issue in {good_fn}"
