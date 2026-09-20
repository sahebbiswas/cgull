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

int test_tp_sprintf_source_escape_via_formatter_before_reject(double d, char *out) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d); // expect: CGULL-048
    sprintf(out, "%s", number_buffer);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return 0;
}

int test_tp_sprintf_reject_goto_into_buffer_use(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d); // expect: CGULL-048
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        goto use_buf;
    }
    return 0;
use_buf:
    puts(number_buffer);
    return -1;
}

int test_tp_sprintf_length_gt_sizeof_alone(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d); // expect: CGULL-048
    if ((length < 0) || ((size_t)length > sizeof(number_buffer))) {
        return -1;
    }
    puts(number_buffer);
    return length;
}

int test_tp_sprintf_sscanf_string_copy_escape(double d, char *out) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d); // expect: CGULL-048
    sscanf(number_buffer, "%s", out);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return 0;
}

int test_tp_sprintf_formatter_self_copy(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d); // expect: CGULL-048
    sprintf(number_buffer, "%s", number_buffer); // expect: CGULL-048
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return 0;
}

int test_tp_sprintf_alias_escape_before_reject(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d); // expect: CGULL-048
    char *p = number_buffer;
    puts(p);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return length;
}

int test_tp_sprintf_address_alias_escape_before_reject(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d); // expect: CGULL-048
    char *p = &number_buffer[0];
    puts(p);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return length;
}

int test_tp_sprintf_length_overwrite_before_reject(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d); // expect: CGULL-048
    length = 0;
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    puts(number_buffer);
    return length;
}
