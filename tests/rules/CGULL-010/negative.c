/* CGULL-010 Negative Test Suite */

#define BUFFER_SIZE 64

void test_tn_literal_bound(void) {
    char buffer[64];
    use(buffer);
}

void test_tn_macro_bound(void) {
    char buffer[BUFFER_SIZE];
    use(buffer);
}
