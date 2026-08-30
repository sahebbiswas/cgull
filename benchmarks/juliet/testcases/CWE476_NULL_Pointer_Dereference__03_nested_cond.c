#include <stdio.h>
#include <stdlib.h>

void CWE476_NULL_Pointer_Dereference__03_nested_cond_bad(void) {
    int *ptr = NULL;
    int flag = 1;
    if (flag) {
        if (1) {
            *ptr = 10;
        }
    }
}

void CWE476_NULL_Pointer_Dereference__03_nested_cond_good(void) {
    int *ptr = NULL;
    int flag = 1;
    if (flag) {
        if (ptr != NULL) {
            *ptr = 10;
        }
    }
}
