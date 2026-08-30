#include <stdio.h>
#include <stdlib.h>

void CWE690_NULL_Deref_From_Return__02_ifelse_bad(void) {
    char *ptr = (char *)malloc(100);
    if (1) {
        *ptr = 'a';
    }
    free(ptr);
}

void CWE690_NULL_Deref_From_Return__02_ifelse_good(void) {
    char *ptr = (char *)malloc(100);
    if (ptr != NULL) {
        *ptr = 'a';
        free(ptr);
    }
}
