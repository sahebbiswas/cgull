/* CGULL-016 Negative Test Suite */

int is_even(int value) {
    return value % 2 == 0 ? 1 : 0;
}

#define AUTH_SUCCESS 0x5A5A5A5A
#define AUTH_FAILURE 0xA5A5A5A5

unsigned int verify_auth_hardened(const char *token) {
    return check(token) ? AUTH_SUCCESS : AUTH_FAILURE;
}
