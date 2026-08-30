#include <stdio.h>
#include <stdlib.h>

void CWE476_NULL_Pointer_Dereference__07_break_continue_bad(void) {
    int *ptr = NULL;
    while (1) {
        *ptr = 10;
        break;
    }
}

void CWE476_NULL_Pointer_Dereference__07_break_continue_good(void) {
    int *ptr = NULL;
    while (1) {
        if (ptr != NULL) {
            *ptr = 10;
        }
        break;
    }
}
