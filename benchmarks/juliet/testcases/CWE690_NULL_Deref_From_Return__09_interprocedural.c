#include <stdio.h>
#include <stdlib.h>

static void CWE690_09_bad_sink(char *ptr) {
    *ptr = 'a';
    free(ptr);
}

void CWE690_NULL_Deref_From_Return__09_interprocedural_bad(void) {
    char *ptr = (char *)malloc(100);
    CWE690_09_bad_sink(ptr);
}

static void CWE690_09_good_sink(char *ptr) {
    if (ptr != NULL) {
        *ptr = 'a';
        free(ptr);
    }
}

void CWE690_NULL_Deref_From_Return__09_interprocedural_good(void) {
    char *ptr = (char *)malloc(100);
    CWE690_09_good_sink(ptr);
}
