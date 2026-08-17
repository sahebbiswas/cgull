/* CGULL-003 Positive Test Suite */
#include <stdlib.h>
#include <stdio.h>

/* True Positive: Simple unchecked malloc */
void test_tp_malloc(void) {
    char *buf = (char *)malloc(1024); // expect: CGULL-003
    buf[0] = 'A';
}

/* True Positive: Simple unchecked calloc */
void test_tp_calloc(void) {
    int *arr = (int *)calloc(10, sizeof(int)); // expect: CGULL-003
    arr[0] = 42;
}

/* True Positive: Simple unchecked realloc */
void test_tp_realloc(char *old_buf) {
    char *new_buf = (char *)realloc(old_buf, 2048); // expect: CGULL-003
    new_buf[0] = 'B';
}

/* False-Negative Regression: Check in else branch does not guard if branch */
void test_fn_check_in_else(int cond) {
    char *p = malloc(64); // expect: CGULL-003
    if (cond) {
        p[0] = 'X';
    } else {
        if (p == NULL) return;
    }
}

/* False-Negative Regression: Logging without return/exit is unsafe */
void test_fn_logging_only(size_t sz) {
    char *p = malloc(sz); // expect: CGULL-003
    if (p == NULL) {
        printf("Error: OOM\n");
    }
    p[0] = 'Z';
}

/* Control-Flow Variation: NULL check only inside loop does not guard post-loop use */
void test_cf_loop_check(int count) {
    char *p = malloc(128); // expect: CGULL-003
    while (count--) {
        if (p == NULL) continue;
    }
    p[0] = 'L';
}

/* Formatting Variation: Multi-line / formatted allocation call */
void test_formatting_multiline(void) {
    int *data = (int *) malloc( // expect: CGULL-003
        100 * sizeof(int)
    );
    data[0] = 1;
}

/* Macro & Type Variation: Struct allocation via macro */
#define MY_ALLOC(size) malloc(size)
struct Session { int id; };

void test_macro_struct_type(void) {
    struct Session *s = MY_ALLOC(sizeof(struct Session)); // expect: CGULL-003
    s->id = 100;
}
