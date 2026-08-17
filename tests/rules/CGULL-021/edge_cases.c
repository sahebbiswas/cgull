/* CGULL-021 Edge Cases Test Suite */
#include <stdlib.h>

void use_ptr(void *p);

/* Uninitialized pointer inside loop body */
void test_edge_loop_uninit(int n) {
    char *buf; // expect: CGULL-021
    while (n--) {
        use_ptr(buf);
    }
}
