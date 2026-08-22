/* CGULL-027 Positive Test Suite */
#include <stdlib.h>
#include <stdio.h>

struct Node {
    int value;
};

/* True Positive: Simple double free */
void test_tp_double_free_simple(struct Node *n) {
    free(n);
    free(n); // expect: CGULL-027
}

/* True Positive: Double free separated by lines */
void test_tp_double_free_separated(char *p) {
    free(p);
    int a = 1;
    a++;
    free(p); // expect: CGULL-027
}

/* False Positive Regression: Reassigned before second free */
void test_fp_reassigned(char *p) {
    free(p);
    p = malloc(10);
    if (p) {
        free(p); /* Safe: newly allocated */
    }
}

/* Control-Flow Variation: Double free inside if */
void test_cf_double_free_if(int cond, char *p) {
    if (cond) {
        free(p);
    } else {
        free(p);
    }

    if (cond) {
        free(p); // expect: CGULL-027
    }
}

/* False Positive Regression: Set to NULL */
void test_fp_set_to_null(char *p) {
    free(p);
    p = NULL;
    free(p); /* Safe: free(NULL) is a no-op */
}

/* True Positive: Double free through direct alias */
void test_tp_double_free_alias(void) {
    char *p = (char *)malloc(16);
    if (!p) return;
    char *q = p;
    free(p);
    free(q); // expect: CGULL-027
}
