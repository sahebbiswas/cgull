#include <stdio.h>
#include <stdlib.h>

void CWE476_NULL_Pointer_Dereference__05_switch_bad(void) {
    int *ptr = NULL;
    switch (6) {
        case 6:
            *ptr = 10;
            break;
        default:
            break;
    }
}

void CWE476_NULL_Pointer_Dereference__05_switch_good(void) {
    int *ptr = NULL;
    switch (6) {
        case 6:
            if (ptr != NULL) {
                *ptr = 10;
            }
            break;
        default:
            break;
    }
}
