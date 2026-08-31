/*
 * Reduced, self-contained adaptation of Juliet 1.3's
 * CWE134_Uncontrolled_Format_String__char_connect_socket_printf_01.
 * The network source is replaced with a deterministic string so this static
 * analysis fixture has no external runtime dependency.
 */
#include <stdio.h>

void CWE134_Uncontrolled_Format_String__printf_01_baseline_bad(void) {
    char data[100] = "%x %x";
    printf(data);
}

void CWE134_Uncontrolled_Format_String__printf_01_baseline_good(void) {
    char data[100] = "%x %x";
    printf("%s", data);
}

/* Juliet's GoodSource/BadSink variant: safe data, syntactically unsafe sink. */
void CWE134_Uncontrolled_Format_String__printf_01_baseline_goodG2B(void) {
    char data[100] = "fixed string";
    printf(data);
}
