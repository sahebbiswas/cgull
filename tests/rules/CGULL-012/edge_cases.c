/* CGULL-012 Edge Cases Test Suite */

int test_edge_nested_argument(void) {
    return atoi(get_text(sizeof(int))); // expect: CGULL-012
}

int test_edge_multiline_call(char *text) {
    return atoi( // expect: CGULL-012
        text
    );
}
