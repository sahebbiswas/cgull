/* CGULL-002 Negative Test Suite */
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

void test_tn_printf(char *input) {
    printf("%s\n", input);
}

void test_tn_fprintf(FILE *f, char *input) {
    fprintf(f, "%s\n", input);
}

void test_tn_sprintf(char *buf, char *input) {
    sprintf(buf, "%s", input);
}

void test_tn_snprintf(char *buf, size_t sz, char *input) {
    snprintf(buf, sz, "%s", input);
}

void test_tn_syslog(int priority, char *input) {
    syslog(priority, "%s", input);
}

void test_tn_vsnprintf(char *buf, size_t sz, va_list args) {
    vsnprintf(buf, sz, "%s", args);
}

/* Local buffers initialized exclusively from literals are safe formats. */
void test_tn_literal_buffer_initializer(void) {
    char format[32] = "fixed string";
    printf(format);
}

void test_tn_literal_pointer_assignment(void) {
    char *format;
    format = "fixed string";
    printf(format);
}
