/* CGULL-006 Negative Test Suite */
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

/* True Negative: Checked multiplication before malloc */
void test_tn_checked_mult(size_t count) {
    if (count > SIZE_MAX / sizeof(int)) return;
    int *buf = malloc(count * sizeof(int));
    (void)buf;
}

/* True Negative: Checked general integer arithmetic near INT_MAX */
void test_tn_checked_int_max_add(void) {
    int data = 2147483647; // INT_MAX
    if (data < 2147483647) {
        int result = data + 1;
        (void)result;
    }
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

/* True Negative: external input is range-checked before arithmetic. */
void test_tn_tainted_checked_add(void) {
    char input[32];
    int data = 0;
    if (fgets(input, sizeof(input), stdin) != NULL) {
        data = atoi(input);
    }
    if (data < INT_MAX) {
        int result = data + 1;
        (void)result;
    }
}

/* True Negative: later trusted assignment clears external-input taint. */
void test_tn_taint_cleared_by_assignment(char **argv) {
    int data = atoi(argv[1]);
    data = 2;
    int result = data * 2;
    (void)result;
}
