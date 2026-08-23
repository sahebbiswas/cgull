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
