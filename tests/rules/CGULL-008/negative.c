/* CGULL-008 Negative Test Suite */

void test_tn_explicit_wipe(void) {
    char password[64];
    use(password);
    explicit_bzero(password, sizeof(password));
}

int test_tn_generic_buffer(void) {
    char buffer[64];
    use(buffer);
    memset(buffer, 0, sizeof(buffer));
    return 0;
}
