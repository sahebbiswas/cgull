/* CGULL-048 Negative Test Suite */

void test_tn_strcpy_literal(void) {
    char buffer[8];
    strcpy(buffer, "hello");
}

void test_tn_strcat_bounded_literals(void) {
    char buffer[8] = "abc";
    strcat(buffer, "xy");
}

void test_tn_sprintf_literal_output(void) {
    char buffer[8];
    sprintf(buffer, "ok");
}

void test_tn_scanf_bounded_string(void) {
    char buffer[8];
    scanf("%7s", buffer);
}

void test_tn_scanf_bounded_scanset(void) {
    char buffer[8];
    scanf("%7[a-z]", buffer);
}

void test_tn_memcpy_owned_by_cgull_044(const char *source, unsigned n) {
    char buffer[8];
    memcpy(buffer, source, n);
}
