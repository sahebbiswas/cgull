/* CGULL-001 Positive Test Suite */

void test_tp_gets(char *buffer) {
    gets(buffer); // expect: CGULL-001
}

void test_tp_sprintf(char *buffer, const char *input) {
    sprintf(buffer, "%s", input); // expect: CGULL-001
}

void test_tp_tmpnam(char *name) {
    tmpnam(name); // expect: CGULL-001
}
