/* CGULL-024 Positive Test Suite */

const char *admin_password = "correct-horse-battery-staple"; // expect: CGULL-024
char api_key[64] = "hardcoded-api-key"; // expect: CGULL-024

void test_tp_local_secret(void) {
    char *auth_token = "embedded-auth-token"; // expect: CGULL-024
    use(auth_token);
}
