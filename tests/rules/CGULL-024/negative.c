/* CGULL-024 Negative Test Suite */

void test_tn_runtime_secret(void) {
    char *api_key = getenv("API_KEY");
    use(api_key);
}

const char *service_endpoint = "https://service.example";

void test_tn_empty_sensitive_value(void) {
    char password[64] = "";
    load_password(password, sizeof(password));
}
