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
