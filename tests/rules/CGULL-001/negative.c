/* CGULL-001 Negative Test Suite */

void test_tn_bounded_input(char *buffer, int size, void *stream) {
    fgets(buffer, size, stream);
}

void test_tn_bounded_format(char *buffer, int size, const char *input) {
    snprintf(buffer, size, "%s", input);
}

void test_tn_similar_identifier(char *buffer) {
    my_gets_wrapper(buffer);
}
