/* CGULL-022 Negative Test Suite */
#include <stdlib.h>

struct Session {
    int id;
};

/* True Negative: Pointer nulled after free */
void test_tn_null_after_free(struct Session *s) {
    free(s);
    s = NULL;
}

/* True Negative: Pointer reassigned after free */
void test_tn_reassigned_after_free(char *p) {
    free(p);
    p = (char *)malloc(32);
    if (p == NULL) return;
    p[0] = 'a';
    free(p);
}

/* False-Positive Regression: UAF in exclusive else branch */
void test_fp_exclusive_branch(int cond, char *p) {
    if (cond) {
        free(p);
    } else {
        p[0] = 'x';
    }
}

/* False-Positive Regression: Switch break prevents reachability */
void test_fp_switch_break(int mode, char *p) {
    switch (mode) {
    case 1:
        free(p);
        break;
    case 2:
        p[0] = 'x';
        break;
    default:
        break;
    }
}
