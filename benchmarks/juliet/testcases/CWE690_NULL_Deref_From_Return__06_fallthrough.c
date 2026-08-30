#include <stdio.h>
#include <stdlib.h>

void CWE690_NULL_Deref_From_Return__06_fallthrough_bad(void) {
    char *ptr = (char *)malloc(100);
    switch (6) {
        case 6:
        case 7:
            *ptr = 'a';
            break;
        default:
            break;
    }
    free(ptr);
}

void CWE690_NULL_Deref_From_Return__06_fallthrough_good(void) {
    char *ptr = (char *)malloc(100);
    switch (6) {
        case 6:
        case 7:
            if (ptr != NULL) {
                *ptr = 'a';
                free(ptr);
            }
            break;
        default:
            break;
    }
}
