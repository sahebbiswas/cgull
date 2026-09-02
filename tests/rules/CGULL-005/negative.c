/* CGULL-005 Negative Test Suite */

int test_tn_generic_compare(const char *left, const char *right) {
    return memcmp(left, right, 4);
}

int test_tn_constant_time_compare(const char *token, const char *expected) {
    return CRYPTO_memcmp(token, expected, 32);
}
