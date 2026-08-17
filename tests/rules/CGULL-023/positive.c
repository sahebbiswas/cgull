/* CGULL-023 Positive Test Suite */

/* True Positive: Scalar variable declared without initialization and returned */
int test_tp_uninit_scalar(int flag) {
    int status; // expect: CGULL-023
    if (flag) {
        status = 1;
    }
    return status;
}

/* False-Negative Regression: Conditional assignment where else branch leaves variable unassigned */
int test_fn_conditional_uninit(int a, int b) {
    int res; // expect: CGULL-023
    if (a > b) {
        res = a - b;
    }
    return res;
}

/* Control-Flow Variation: Uninitialized variable read inside loop */
int test_cf_loop_uninit(int n) {
    int total; // expect: CGULL-023
    while (n--) {
        total += n;
    }
    return total;
}

/* Formatting & Type Variation: Typedef scalar variable uninitialized */
typedef unsigned int uint32_t;
uint32_t test_formatting_typedef_uninit(int cond) {
    uint32_t   count ; // expect: CGULL-023
    if (cond) count = 10U;
    return count;
}
