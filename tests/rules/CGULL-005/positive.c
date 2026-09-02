/* CGULL-005 Positive Test Suite */

int test_tp_token_compare(const char *token, const char *expected_token) {
    return memcmp(token, expected_token, 32); // expect: CGULL-005
}

int test_tp_password_compare(const char *password, const char *expected) {
    return strcmp(password, expected); // expect: CGULL-005
}
