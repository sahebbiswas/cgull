/* CGULL-048 Positive Test Suite */

void test_tp_strcpy_unknown_source(const char *source) {
    char buffer[8];
    strcpy(buffer, source); // expect: CGULL-048
}

void test_tp_strcat_unknown_result(const char *source) {
    char buffer[8] = "abc";
    strcat(buffer, source); // expect: CGULL-048
}

void test_tp_sprintf_dynamic_output(const char *source) {
    char buffer[8];
    sprintf(buffer, "%s", source); // expect: CGULL-048
}

void test_tp_gets_unbounded_input(void) {
    char buffer[8];
    gets(buffer); // expect: CGULL-048
}

void test_tp_scanf_unbounded_string(void) {
    char buffer[8];
    scanf("%s", buffer); // expect: CGULL-048
}

void test_tp_scanf_unbounded_scanset(void) {
    char buffer[8];
    scanf("%[a-z]", buffer); // expect: CGULL-048
}

void test_tp_sprintf_use_without_length_check(double d) {
    char number_buffer[26];
    sprintf(number_buffer, "%1.15g", d); // expect: CGULL-048
    puts(number_buffer);
}

void test_tp_sprintf_use_before_length_check(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d); // expect: CGULL-048
    puts(number_buffer);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return;
    }
}
