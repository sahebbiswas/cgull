/* CGULL-016 Positive Test Suite */

int verify_auth_token(const char *token) { // expect: CGULL-016
    if (check(token)) {
        return 1;
    }
    return 0;
}

int validate_token(const char *token) { // expect: CGULL-016
    if (token != 0) {
        return 1;
    }
    return 0;
}
