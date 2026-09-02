/* CGULL-013 Edge Cases Test Suite */

void test_edge_multiline_condition(int left, int right) {
    if ( // expect: CGULL-013
        left > 0 &&
        right > 0
    )
        process(left, right);
}

void test_edge_do_while(int count) {
    do {
        count--;
    } while (count > 0);
}
