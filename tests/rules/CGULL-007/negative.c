/* CGULL-007 Negative Test Suite */

/* True Negative: Index within array bounds */
void test_tn_valid_index(void) {
    int table[10];
    table[9] = 42;
}

/* True Negative: Index zero on non-empty array */
void test_tn_first_element(void) {
    char buf[16];
    buf[0] = 'A';
}

/* False-Positive Regression: Array declaration line not flagged as indexing */
void test_fp_declaration_line(void) {
    int buffer[100];
    (void)buffer;
}
