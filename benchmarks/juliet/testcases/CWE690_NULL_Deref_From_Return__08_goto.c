#include <stdio.h>
#include <stdlib.h>

void CWE690_NULL_Deref_From_Return__08_goto_bad(void) {
    char *ptr = (char *)malloc(100);
    goto sink;
sink:
    *ptr = 'a';
    free(ptr);
}

void CWE690_NULL_Deref_From_Return__08_goto_good(void) {
    char *ptr = (char *)malloc(100);
    goto sink;
sink:
    if (ptr != NULL) {
        *ptr = 'a';
        free(ptr);
    }
}
