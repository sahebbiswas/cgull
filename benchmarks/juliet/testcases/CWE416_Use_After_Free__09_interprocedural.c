#include <stdio.h>
#include <stdlib.h>

static void CWE416_09_bad_sink(char *ptr) {
    *ptr = 'a';
}

void CWE416_Use_After_Free__09_interprocedural_bad(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    free(ptr);
    CWE416_09_bad_sink(ptr);
}

static void CWE416_09_good_sink(char *ptr) {
    *ptr = 'a';
    free(ptr);
}

void CWE416_Use_After_Free__09_interprocedural_good(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    CWE416_09_good_sink(ptr);
}
