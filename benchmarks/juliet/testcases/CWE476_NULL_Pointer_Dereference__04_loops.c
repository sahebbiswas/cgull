#include <stdio.h>
#include <stdlib.h>

void CWE476_NULL_Pointer_Dereference__04_loops_bad(void) {
    int *ptr = NULL;
    for (int i = 0; i < 1; i++) {
        *ptr = 10;
    }
}

void CWE476_NULL_Pointer_Dereference__04_loops_good(void) {
    int *ptr = NULL;
    for (int i = 0; i < 1; i++) {
        if (ptr != NULL) {
            *ptr = 10;
        }
    }
}
