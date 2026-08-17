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
