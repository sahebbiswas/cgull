#include <stdio.h>
#include <stdlib.h>

void CWE416_Use_After_Free__07_break_continue_bad(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    free(ptr);
    while (1) {
        *ptr = 'a';
        break;
    }
}

void CWE416_Use_After_Free__07_break_continue_good(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    while (1) {
        *ptr = 'a';
        break;
    }
    free(ptr);
}
