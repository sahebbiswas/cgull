#include <stdio.h>
#include <stdlib.h>

void CWE690_NULL_Deref_From_Return__01_baseline_bad(void) {
    char *ptr = (char *)malloc(100);
    *ptr = 'a';
    free(ptr);
}

void CWE690_NULL_Deref_From_Return__01_baseline_good(void) {
    char *ptr = (char *)malloc(100);
    if (ptr != NULL) {
        *ptr = 'a';
        free(ptr);
    }
}
