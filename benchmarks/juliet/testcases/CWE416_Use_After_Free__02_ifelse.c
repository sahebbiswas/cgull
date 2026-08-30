#include <stdio.h>
#include <stdlib.h>

void CWE416_Use_After_Free__02_ifelse_bad(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    free(ptr);
    if (1) {
        *ptr = 'a';
    }
}

void CWE416_Use_After_Free__02_ifelse_good(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    if (1) {
        *ptr = 'a';
    }
    free(ptr);
}
