/* CGULL-004 Positive Test Suite */
#include <stddef.h>

struct Config {
    int value;
};

/* True Positive: Direct pointer dereference without NULL check */
int test_tp_pointer_deref(int *data) {
    *data = 100; // expect: CGULL-004
    return 0;
}

/* True Positive: Struct pointer field access without NULL check */
int test_tp_struct_deref(struct Config *cfg) {
    cfg->value = 42; // expect: CGULL-004
    return cfg->value;
}

/* True Positive: Array indexing on pointer param without NULL check */
int test_tp_array_index(char *buffer) {
    buffer[0] = 'X'; // expect: CGULL-004
    return 0;
}

/* Control-Flow Variation: NULL check only inside loop does not guard post-loop deref */
int test_cf_loop_check_param(int *p, int n) {
    while (n--) {
        if (p == NULL) continue;
    }
    *p = 1; // expect: CGULL-004
    return 0;
}

/* Formatting & Type Variation: Typedef pointer parameter without check */
typedef unsigned char uint8_t;
void test_formatting_typedef_ptr(uint8_t *
    buf_ptr) {
    *buf_ptr = 0xFF; // expect: CGULL-004
}

/* Macro & Type Variation: Multiple parameters, one unchecked */
void test_macro_multi_params(int *a, char *b) {
    if (a == NULL) return;
    *a = 10;
    *b = 'K'; // expect: CGULL-004
}

/* True Positive: Direct local pointer assigned NULL and dereferenced */
void test_tp_direct_null_assignment(void) {
    char *data;
    data = NULL;
    data[0] = 'A'; // expect: CGULL-004
}

/* True Positive: Inverted NULL check dereference */
void test_tp_inverted_null_check(void) {
    int *intPointer = NULL;
    if (intPointer == NULL) {
        *intPointer = 42; // expect: CGULL-004
    }
}
