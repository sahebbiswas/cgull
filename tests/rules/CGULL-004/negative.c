/* CGULL-004 Negative Test Suite */
#include <stddef.h>
#include <assert.h>

struct Config {
    int value;
};

/* True Negative: Early return on NULL check */
int test_tn_checked_param(int *data) {
    if (data == NULL) return -1;
    *data = 100;
    return 0;
}

/* True Negative: Negated guard clause */
int test_tn_negated_guard(struct Config *cfg) {
    if (!cfg) return -1;
    cfg->value = 42;
    return 0;
}

/* False-Positive Regression: Assert guard dominating dereference */
int test_fp_assert_guard(int *p) {
    assert(p != NULL);
    *p = 1;
    return 0;
}

/* False-Positive Regression: Scalar non-pointer parameter */
int test_fp_scalar_param(int val) {
    val = val + 1;
    return val;
}

/* True Negative: Local pointer assigned valid buffer before dereference */
void test_tn_assigned_valid_buffer(void) {
    char *data;
    char buffer[100] = "hello";
    data = buffer;
    data[0] = 'H';
}

/* True Negative: Correct non-null check before dereference */
void test_tn_correct_not_null_check(void) {
    int *intPointer = NULL;
    int val = 10;
    intPointer = &val;
    if (intPointer != NULL) {
        *intPointer = 42;
    }
}

/* False-Positive Regression (#551): short-circuit OR null checks before field access */
typedef struct CJSON551 { int type; char *valuestring; double valuedouble; unsigned offset; unsigned length; char *content; } CJSON551;
int test_fp_short_circuit_or_null_checks(const CJSON551 *a, const CJSON551 *b) {
    if ((a == 0) || (b == 0) || ((a->type & 0xFF) != (b->type & 0xFF))) {
        return 0;
    }
    return a->type;
}

/* False-Positive Regression (#551): short-circuit AND null checks before field access */
int test_fp_short_circuit_and_null_checks(const CJSON551 *a, const CJSON551 *b) {
    if (a != 0 && b != 0 && (a->type == b->type)) {
        return 1;
    }
    return 0;
}

/* False-Positive Regression (#551): negated comparison must guard later deref in the condition */
int test_fp_finding_not_on_negated_null_check(CJSON551 *p) {
    if (!(p == 0) && p->type == 1) {
        return 1;
    }
    return 0;
}

/* False-Positive Regression (#551): callee Is*-style predicate guards later deref */
int test_fp_callee_is_style_null_check_pred(const CJSON551 *item) {
    if (item == 0) {
        return 0;
    }
    return (item->type & 0xFF) == 4;
}
char *test_fp_callee_is_style_getter(const CJSON551 *item) {
    if (!test_fp_callee_is_style_null_check_pred(item)) {
        return 0;
    }
    return item->valuestring;
}

/* False-Positive Regression (#551): cannot_access-style macro must not leave buffer unchecked */
#define test_fp_can_access_at_index(buffer, index) ((buffer != 0) && ((buffer)->offset + (index) < (buffer)->length))
#define test_fp_cannot_access_at_index(buffer, index) (!test_fp_can_access_at_index(buffer, index))
char test_fp_cannot_access_macro_then_use(CJSON551 *buffer, unsigned index) {
    if (test_fp_cannot_access_at_index(buffer, index)) {
        return 0;
    }
    return buffer->content[buffer->offset + index];
}

/* True Negative (#559): dominating NULL guard before pointer arithmetic */
const char *test_tn_guarded_pointer_plus_offset(const char *p, int off) {
    if (p) return p + off;
    return 0;
}

/* True Negative (#559): early return guard before offset + pointer */
const char *test_tn_guarded_offset_plus_pointer(const char *p, int off) {
    if (p == 0) return 0;
    return off + p;
}

/* False-Positive Regression (#559): integer addition must stay silent */
int test_fp_integer_addition(int a, int b) {
    return a + b;
}
