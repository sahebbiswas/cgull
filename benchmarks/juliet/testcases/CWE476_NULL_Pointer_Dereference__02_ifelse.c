#include <stdio.h>
#include <stdlib.h>

void CWE476_NULL_Pointer_Dereference__02_ifelse_bad(void) {
    int *ptr = NULL;
    if (1) {
        *ptr = 10;
    } else {
        printf("Safe\n");
    }
}

void CWE476_NULL_Pointer_Dereference__02_ifelse_good(void) {
    int *ptr = NULL;
    if (ptr != NULL) {
        *ptr = 10;
    } else {
        printf("Safe\n");
    }
}
