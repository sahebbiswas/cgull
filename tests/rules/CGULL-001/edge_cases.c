/* CGULL-001 Edge Cases Test Suite */

void test_edge_unbounded_scan(char *buffer) {
    scanf("%s", buffer); // expect: CGULL-001
}

void test_edge_bounded_scan(char *buffer) {
    scanf("%31s", buffer);
}

void test_edge_string_literal(void) {
    const char *text = "gets(buffer) is unsafe";
    (void)text;
}
