/* CGULL-021 Negative Test Suite */
#include <stdlib.h>

void use_ptr(void *p);

/* True Negative: Pointer initialized to NULL */
void test_tn_null_init(void) {
    char *secret_key = NULL;
    use_ptr(secret_key);
}

/* True Negative: Pointer initialized with malloc */
void test_tn_alloc_init(void) {
    int *data = (int *)malloc(sizeof(int));
    if (data) {
        use_ptr(data);
        free(data);
    }
}

/* False-Positive Regression: Pointer assigned on all branches before use */
void test_fp_all_branches_assigned(int cond) {
    char *p;
    if (cond) {
        p = (char *)malloc(16);
    } else {
        p = NULL;
    }
    if (p) {
        use_ptr(p);
        free(p);
    }
}
