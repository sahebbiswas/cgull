#include <stdio.h>
#include <stdlib.h>

void CWE690_NULL_Deref_From_Return__03_nested_cond_bad(void) {
    char *ptr = (char *)malloc(100);
    if (1) {
        if (1) {
            *ptr = 'a';
        }
    }
    free(ptr);
}

void CWE690_NULL_Deref_From_Return__03_nested_cond_good(void) {
    char *ptr = (char *)malloc(100);
    if (1) {
        if (ptr != NULL) {
            *ptr = 'a';
            free(ptr);
        }
    }
}
