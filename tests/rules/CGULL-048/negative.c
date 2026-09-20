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

int test_tn_sprintf_post_length_capacity_reject(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    puts(number_buffer);
    return length;
}

int test_tn_sprintf_cjson_print_number_defense(double d) {
    unsigned char number_buffer[26];
    int length;
    double test;
    length = sprintf((char*)number_buffer, "%1.15g", d);
    if ((sscanf((char*)number_buffer, "%lg", &test) != 1)) {
        length = sprintf((char*)number_buffer, "%1.17g", d);
    }
    if ((length < 0) || (length > (int)(sizeof(number_buffer) - 1))) {
        return 0;
    }
    return length;
}

void fatal(const char *msg);

int test_tn_sprintf_reject_via_fatal(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        fatal("overflow");
    }
    puts(number_buffer);
    return length;
}

int test_tn_sprintf_alias_then_reject_then_use(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    char *p = number_buffer;
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    puts(p);
    return length;
}

int test_tn_sprintf_address_alias_then_reject_then_use(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    char *p = &number_buffer[0];
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    puts(p);
    return length;
}

