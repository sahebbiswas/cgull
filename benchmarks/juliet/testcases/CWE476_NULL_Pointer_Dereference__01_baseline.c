#include <stdio.h>
#include <stdlib.h>

void CWE476_NULL_Pointer_Dereference__01_baseline_bad(void) {
    int *ptr = NULL;
    *ptr = 10;
}

void CWE476_NULL_Pointer_Dereference__01_baseline_good(void) {
    int *ptr = NULL;
    if (ptr != NULL) {
        *ptr = 10;
    }
}
