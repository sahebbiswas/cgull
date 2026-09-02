/* CGULL-014 Negative Test Suite */

#define BUFFER_SIZE 4096

void test_tn_named_bound(void) {
    char buffer[BUFFER_SIZE];
    use(buffer);
}

void test_tn_small_exempt_bound(void) {
    int pair[2];
    use(pair);
}
