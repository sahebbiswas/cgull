#include <stdio.h>
#include <stdlib.h>

void CWE416_Use_After_Free__08_goto_bad(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    free(ptr);
    goto sink;
sink:
    *ptr = 'a';
}

void CWE416_Use_After_Free__08_goto_good(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    goto sink;
sink:
    *ptr = 'a';
    free(ptr);
}
