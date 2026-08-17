/* CGULL-003 Negative Test Suite */
#include <stdlib.h>

/* True Negative: Checked malloc with early return */
void test_tn_checked_malloc(void) {
    char *buf = (char *)malloc(1024);
    if (buf == NULL) {
        return;
    }
    buf[0] = 'A';
}

/* True Negative: Checked with !ptr */
void test_tn_negated_check(void) {
    int *arr = (int *)calloc(10, sizeof(int));
    if (!arr) {
        return;
    }
    arr[0] = 42;
}

/* False-Positive Regression: Early return guard dominating later use */
void test_fp_early_return_guard(size_t size) {
    char *p = malloc(size);
    if (p == NULL) return;
    p[0] = 'a';
}

/* False-Positive Regression: Assert guard */
void test_fp_assert_guard(size_t size) {
    char *p = malloc(size);
    assert(p != NULL);
    p[0] = 'a';
}

/* Control-Flow Variation: Early return on NULL check */
void test_clean_early_exit(size_t len) {
    char *buf = malloc(len);
    if (buf == NULL)
        return;
    buf[0] = 'C';
    free(buf);
}
