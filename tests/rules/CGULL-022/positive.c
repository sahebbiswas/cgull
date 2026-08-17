/* CGULL-022 Positive Test Suite */
#include <stdlib.h>
#include <stdio.h>

struct Session {
    int id;
};

/* True Positive: Simple dereference after free */
void test_tp_uaf_struct(struct Session *s) {
    free(s);
    printf("Session ID: %d\n", s->id); // expect: CGULL-022
}

/* True Positive: Array access after free */
void test_tp_uaf_array(char *p) {
    free(p);
    p[0] = 'X'; // expect: CGULL-022
}

/* False-Negative Regression: UAF follows switch fallthrough */
void test_fn_uaf_switch_fallthrough(int mode, char *p) {
    switch (mode) {
    case 1:
        free(p);
        /* fallthrough */
    case 2:
        p[0] = 'a'; // expect: CGULL-022
        break;
    default:
        break;
    }
}

/* Control-Flow Variation: UAF after if statement without return/exit */
void test_cf_uaf_after_if(int cond, char *p) {
    if (cond) free(p);
    p[0] = 'z'; // expect: CGULL-022
}

/* Formatting & Type Variation: Pointer passed to function after free */
void test_formatting_uaf_call(char *msg) {
    free(msg);
    printf("%s", msg); // expect: CGULL-022
}
