#include <stdio.h>
#include <stdlib.h>

void CWE690_NULL_Deref_From_Return__04_loops_bad(void) {
    char *ptr = (char *)malloc(100);
    for (int i = 0; i < 1; i++) {
        *ptr = 'a';
    }
    free(ptr);
}

void CWE690_NULL_Deref_From_Return__04_loops_good(void) {
    char *ptr = (char *)malloc(100);
    for (int i = 0; i < 1; i++) {
        if (ptr != NULL) {
            *ptr = 'a';
            free(ptr);
        }
    }
}
