/* CGULL-002 Positive Test Suite */
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

void test_tp_printf(char *input) {
    printf(input); // expect: CGULL-002
}

void test_tp_fprintf(FILE *f, char *input) {
    fprintf(f, input); // expect: CGULL-002
}

void test_tp_sprintf(char *buf, char *input) {
    sprintf(buf, input); // expect: CGULL-002
}

void test_tp_snprintf(char *buf, size_t sz, char *input) {
    snprintf(buf, sz, input); // expect: CGULL-002
}

void test_tp_syslog(int priority, char *input) {
    syslog(priority, input); // expect: CGULL-002
}

void test_tp_vprintf(char *fmt, va_list args) {
    vprintf(fmt); // expect: CGULL-002
}

void test_tp_vfprintf(FILE *f, char *fmt, va_list args) {
    vfprintf(f, fmt, args); // expect: CGULL-002
}

void test_tp_vsnprintf(char *buf, size_t sz, char *fmt, va_list args) {
    vsnprintf(buf, sz, fmt, args); // expect: CGULL-002
}

void test_tp_unknown_uninitialized_format(void) {
    char format[32];
    printf(format); // expect: CGULL-002
}

void test_tp_unknown_assignment_overrides_literal(char *input) {
    char *format = "fixed string";
    format = input;
    printf(format); // expect: CGULL-002
}

void test_tp_literal_format_directive(void) {
    char format[] = "%x";
    printf(format); // expect: CGULL-002
}

void test_tp_external_write_after_literal_initializer(void) {
    char format[32] = "fixed string";
    fgets(format, sizeof(format), stdin);
    printf(format); // expect: CGULL-002
}
