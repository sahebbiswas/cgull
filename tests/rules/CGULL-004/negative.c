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
