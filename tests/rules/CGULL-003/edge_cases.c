/* CGULL-003 Edge Cases Test Suite */
#include <stdlib.h>

/* Reassignment after unchecked allocation: new check protects new ptr */
void test_edge_reassign(void) {
    char *p = malloc(32); // expect: CGULL-003
    p[0] = 'a';
    p = malloc(64);
    if (p == NULL) return;
    p[0] = 'b';
}

/* Unchecked allocation inside branch */
void test_edge_conditional_alloc(int flag) {
    if (flag) {
        int *data = malloc(sizeof(int)); // expect: CGULL-003
        *data = 5;
    }
}
