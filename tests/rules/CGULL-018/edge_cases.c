/* CGULL-018 Edge Cases Test Suite */

void test_edge_spacing(int error) {
    if (error) {
        goto    fail ; // expect: CGULL-018
    }
fail:
    return;
}

void test_edge_comment_only(void) {
    /* goto cleanup; */
}
