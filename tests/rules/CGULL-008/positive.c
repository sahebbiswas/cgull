/* CGULL-008 Positive Test Suite */

int test_tp_password_wipe(void) {
    char password[64];
    use(password);
    memset(password, 0, sizeof(password)); // expect: CGULL-008
    return 0;
}

void test_tp_secret_key_wipe(void) {
    char secret_key[32];
    use(secret_key);
    memset(secret_key, 0, sizeof(secret_key)); // expect: CGULL-008
}
