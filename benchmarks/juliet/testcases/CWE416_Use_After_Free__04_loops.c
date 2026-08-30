#include <stdio.h>
#include <stdlib.h>

void CWE416_Use_After_Free__04_loops_bad(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    free(ptr);
    for (int i = 0; i < 1; i++) {
        *ptr = 'a';
    }
}

void CWE416_Use_After_Free__04_loops_good(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    for (int i = 0; i < 1; i++) {
        *ptr = 'a';
    }
    free(ptr);
}
