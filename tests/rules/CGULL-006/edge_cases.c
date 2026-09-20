/* CGULL-006 Edge Cases Test Suite */
#include <stdlib.h>
#include <stdint.h>

/* Arithmetic with sizeof type cast */
void test_edge_sizeof_cast(size_t n) {
    double *arr = malloc(n * 8); // expect: CGULL-006
    (void)arr;
}

/* Checked bounds before allocation */
void test_edge_checked_bounds_and_alloc(size_t n) {
    if (n > 100) return;
    int *buf = malloc(n * 4);
    (void)buf;
}

/* Edge: constant-only size bump without INT_MAX gate stays quiet (#560) */
void *test_edge_const_bump_alloc(void) {
    size_t n = 10;
    n += 1;
    return malloc(n);
}

/* Edge: unchecked var accumulation into realloc size without INT_MAX gate (#560) */
void *test_edge_accum_offset_realloc(void *buf, size_t needed, size_t offset) {
    needed += offset; // expect: CGULL-006
    return realloc(buf, needed);
}
