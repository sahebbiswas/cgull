/* CGULL-014 Positive Test Suite */

void test_tp_large_buffer(void) {
    char buffer[4096]; // expect: CGULL-014
    use(buffer);
}

void test_tp_lookup_table(void) {
    int table[512]; // expect: CGULL-014
    use(table);
}
