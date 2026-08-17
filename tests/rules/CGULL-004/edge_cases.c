/* CGULL-004 Edge Cases Test Suite */
#include <stddef.h>

/* Const pointer parameter dereferenced without check */
int test_edge_const_ptr(const int *input) {
    int val = *input; // expect: CGULL-004
    return val;
}

/* Pointer parameter reassignment before dereference */
int test_edge_reassigned_param(int *data) {
    int local = 5;
    data = &local;
    *data = 10;
    return 0;
}
