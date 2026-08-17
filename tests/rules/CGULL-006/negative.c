/* CGULL-006 Negative Test Suite */
#include <stdlib.h>
#include <stdint.h>

/* True Negative: Checked multiplication before malloc */
void test_tn_checked_mult(size_t count) {
    if (count > SIZE_MAX / sizeof(int)) return;
    int *buf = malloc(count * sizeof(int));
    (void)buf;
}

/* True Negative: Fixed constant size without variable arithmetic */
void test_tn_constant_size(void) {
    char *buf = malloc(1024);
    (void)buf;
}

/* False-Positive Regression: Bounds check using MAX_ constant */
#define MAX_ELEMENTS 1000
void test_fp_max_constant_check(size_t count) {
    if (count > MAX_ELEMENTS) return;
    int *buf = malloc(count * sizeof(int));
    (void)buf;
}
