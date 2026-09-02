/* CGULL-012 Negative Test Suite */

long test_tn_strtol(char *text) {
    char *endptr;
    return strtol(text, &endptr, 10);
}

int test_tn_similar_identifier(char *text) {
    return atoi_checked(text);
}
