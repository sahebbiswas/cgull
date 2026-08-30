#include <stdio.h>
#include <stdlib.h>

void CWE690_NULL_Deref_From_Return__05_switch_bad(void) {
    char *ptr = (char *)malloc(100);
    switch (6) {
        case 6:
            *ptr = 'a';
            break;
        default:
            break;
    }
    free(ptr);
}

void CWE690_NULL_Deref_From_Return__05_switch_good(void) {
    char *ptr = (char *)malloc(100);
    switch (6) {
        case 6:
            if (ptr != NULL) {
                *ptr = 'a';
                free(ptr);
            }
            break;
        default:
            break;
    }
}
