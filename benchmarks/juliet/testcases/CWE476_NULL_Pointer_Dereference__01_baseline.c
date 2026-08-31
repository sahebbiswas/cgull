#include <stdio.h>
#include <stdlib.h>

void CWE476_NULL_Pointer_Dereference__01_baseline_bad(void) {
    /* Direct NULL dereference fixture for CGULL-004, not CGULL-003. */
    int *ptr = NULL;
    *ptr = 10;
}

void CWE476_NULL_Pointer_Dereference__01_baseline_good(void) {
    int *ptr = NULL;
    if (ptr != NULL) {
        *ptr = 10;
    }
}
