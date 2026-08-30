#include <stdio.h>
#include <stdlib.h>

void CWE416_Use_After_Free__06_fallthrough_bad(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    free(ptr);
    switch (6) {
        case 6:
        case 7:
            *ptr = 'a';
            break;
        default:
            break;
    }
}

void CWE416_Use_After_Free__06_fallthrough_good(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
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
