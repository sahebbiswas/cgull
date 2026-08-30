#include <stdio.h>
#include <stdlib.h>

void CWE476_NULL_Pointer_Dereference__06_fallthrough_bad(void) {
    int *ptr = NULL;
    switch (6) {
        case 6:
        case 7:
            *ptr = 10;
            break;
        default:
            break;
    }
}

void CWE476_NULL_Pointer_Dereference__06_fallthrough_good(void) {
    int *ptr = NULL;
    switch (6) {
        case 6:
        case 7:
            if (ptr != NULL) {
                *ptr = 10;
            }
            break;
        default:
            break;
    }
}
