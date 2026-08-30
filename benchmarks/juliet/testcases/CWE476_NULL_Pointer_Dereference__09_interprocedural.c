#include <stdio.h>
#include <stdlib.h>

static void CWE476_09_bad_sink(int *ptr) {
    *ptr = 10;
}

void CWE476_NULL_Pointer_Dereference__09_interprocedural_bad(void) {
    int *ptr = NULL;
    CWE476_09_bad_sink(ptr);
}

static void CWE476_09_good_sink(int *ptr) {
    if (ptr != NULL) {
        *ptr = 10;
    }
}

void CWE476_NULL_Pointer_Dereference__09_interprocedural_good(void) {
    int *ptr = NULL;
    CWE476_09_good_sink(ptr);
}
