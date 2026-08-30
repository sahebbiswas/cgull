#include <stdio.h>
#include <stdlib.h>

void CWE476_NULL_Pointer_Dereference__08_goto_bad(void) {
    int *ptr = NULL;
    goto sink;
sink:
    *ptr = 10;
}

void CWE476_NULL_Pointer_Dereference__08_goto_good(void) {
    int *ptr = NULL;
    goto sink;
sink:
    if (ptr != NULL) {
        *ptr = 10;
    }
}
