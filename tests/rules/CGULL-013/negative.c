/* CGULL-013 Negative Test Suite */

void test_tn_braced_if(int error) {
    if (error) {
        handle_error();
    } else {
        recover();
    }
}

void test_tn_braced_loop(int count) {
    while (count > 0) {
        count--;
    }
}
