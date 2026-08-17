/* CGULL-021 Positive Test Suite */
#include <stdlib.h>

void use_ptr(void *p);

/* True Positive: Wild pointer declared without initialization and read */
void test_tp_uninit_ptr(void) {
    char *secret_key; // expect: CGULL-021
    use_ptr(secret_key);
}

/* False-Negative Regression: Pointer assigned only conditionally in one branch */
void test_fn_conditional_ptr_assign(int cond) {
    char *p; // expect: CGULL-021
    if (cond) {
        p = (char *)malloc(16);
    }
    use_ptr(p);
}

/* Formatting Variation: Multi-pointer declaration with spaces */
void test_formatting_multi_ptr(void) {
    int  *  raw_ptr ; // expect: CGULL-021
    use_ptr(raw_ptr);
}

/* Macro & Type Variation: Typedef pointer variable uninitialized */
typedef char * StringPtr;
void test_macro_type_uninit(void) {
    char *   token ; // expect: CGULL-021
    use_ptr(token);
}
