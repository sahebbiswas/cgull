/* CGULL-015 Edge Cases Test Suite */

int test_edge_spaced_negative(void) {
    int shifted = - 1 << 3; // expect: CGULL-015
    return shifted;
}

int test_edge_positive_signed_literal(void) {
    int shifted = 1 << 3;
    return shifted;
}
