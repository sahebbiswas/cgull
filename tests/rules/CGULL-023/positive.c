/* CGULL-023 Positive Test Suite */

/* True Positive: Scalar variable declared without initialization and returned */
int test_tp_uninit_scalar(int flag) {
    int status;
    if (flag) {
        status = 1;
    }
    return status; // expect: CGULL-023
}

/* False-Negative Regression: Conditional assignment where else branch leaves variable unassigned */
int test_fn_conditional_uninit(int a, int b) {
    int res;
    if (a > b) {
        res = a - b;
    }
    return res; // expect: CGULL-023
}

/* Control-Flow Variation: Uninitialized variable read inside loop */
int test_cf_loop_uninit(int n) {
    int total;
    while (n--) {
        total += n;
    }
    return total; // expect: CGULL-023
}

/* Formatting & Type Variation: Typedef scalar variable uninitialized */
typedef unsigned int uint32_t;
uint32_t test_formatting_typedef_uninit(int cond) {
    uint32_t   count ;
    if (cond) count = 10U;
    return count; // expect: CGULL-023
}
