/* CGULL-018 Negative Test Suite */

void test_tn_structured_cleanup(int error) {
    if (error) {
        release_resources();
        return;
    }
    continue_work();
}

void test_tn_label_like_identifier(void) {
    int goto_count = 0;
    use(goto_count);
}
