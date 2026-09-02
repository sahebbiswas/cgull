/* CGULL-015 Positive Test Suite */

int test_tp_negative_left_shift(void) {
    int shifted = -1 << 4; // expect: CGULL-015
    return shifted;
}

int test_tp_negative_right_shift(void) {
    int shifted = -8 >> 1; // expect: CGULL-015
    return shifted;
}
