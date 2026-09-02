/* CGULL-018 Positive Test Suite */

void test_tp_cleanup_jump(int error) {
    if (error) {
        goto cleanup; // expect: CGULL-018
    }
cleanup:
    release_resources();
}

void test_tp_retry_jump(int ready) {
retry:
    if (!ready) goto retry; // expect: CGULL-018
}
