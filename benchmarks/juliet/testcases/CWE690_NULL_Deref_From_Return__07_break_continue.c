#include <stdio.h>
#include <stdlib.h>

void CWE690_NULL_Deref_From_Return__07_break_continue_bad(void) {
    char *ptr = (char *)malloc(100);
    while (1) {
        *ptr = 'a';
        break;
    }
    free(ptr);
}

void CWE690_NULL_Deref_From_Return__07_break_continue_good(void) {
    char *ptr = (char *)malloc(100);
    while (1) {
        if (ptr != NULL) {
            *ptr = 'a';
            free(ptr);
        }
        break;
    }
}
