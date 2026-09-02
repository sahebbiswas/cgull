/* CGULL-012 Positive Test Suite */

int test_tp_atoi(char *text) {
    return atoi(text); // expect: CGULL-012
}

long test_tp_atol(char *text) {
    return atol(text); // expect: CGULL-012
}

long long test_tp_atoll(char *text) {
    return atoll(text); // expect: CGULL-012
}
