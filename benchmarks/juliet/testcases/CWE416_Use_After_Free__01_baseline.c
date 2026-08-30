#include <stdio.h>
#include <stdlib.h>

void CWE416_Use_After_Free__01_baseline_bad(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    free(ptr);
    *ptr = 'a';
}

void CWE416_Use_After_Free__01_baseline_good(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    *ptr = 'a';
    free(ptr);
}
