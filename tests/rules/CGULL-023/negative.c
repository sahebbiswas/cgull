/* CGULL-023 Negative Test Suite */

/* True Negative: Scalar variable initialized at declaration */
int test_tn_initialized_at_decl(int flag) {
    int status = 0;
    if (flag) {
        status = 1;
    }
    return status;
}

/* True Negative: Assigned on all branches before read */
int test_tn_assigned_all_branches(int flag) {
    int status;
    if (flag) {
        status = 1;
    } else {
        status = 0;
    }
    return status;
}

/* False-Positive Regression: Volatile variable (hardware register / MMIO read) */
int test_fp_volatile_var(void) {
    volatile int hw_status;
    return hw_status;
}
