/* CGULL-006 Positive Test Suite */
#include <stdlib.h>

/* True Positive: Unchecked multiplication in malloc argument */
void test_tp_malloc_mult(int count) {
    int *buf = malloc(count * 4); // expect: CGULL-006
    (void)buf;
}

/* True Positive: Unchecked addition in malloc argument */
void test_tp_malloc_add(size_t base_len, size_t extra) {
    char *buf = malloc(base_len + extra); // expect: CGULL-006
    (void)buf;
}

/* Formatting Variation: Multi-line / space variations in malloc arithmetic */
void test_formatting_multiline_alloc(size_t num) {
    void *ptr = malloc(num * 64); // expect: CGULL-006
    (void)ptr;
}

/* Macro Variation: Unchecked multiplication in macro-expanded size */
#define ALLOC_ARRAY(n, sz) malloc(n * sz) // expect: CGULL-006
void test_macro_mult(size_t n) {
    char *arr = ALLOC_ARRAY(n, 128);
    (void)arr;
}
