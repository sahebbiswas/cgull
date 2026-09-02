/* CGULL-024 Edge Cases Test Suite */

void test_edge_qualified_array(void) {
    const char private_key[32] = "plaintext-private-key"; // expect: CGULL-024
    use(private_key);
}

void test_edge_similar_identifier(void) {
    const char *monkey = "banana";
    use(monkey);
}
