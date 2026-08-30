#include <stdio.h>
#include <stdlib.h>

void CWE416_Use_After_Free__05_switch_bad(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    free(ptr);
    switch (6) {
        case 6:
            *ptr = 'a';
            break;
        default:
            break;
    }
}

void CWE416_Use_After_Free__05_switch_good(void) {
    char *ptr = (char *)malloc(100);
    if (ptr == NULL) return;
    switch (6) {
        case 6:
            *ptr = 'a';
            break;
        default:
            break;
    }
    free(ptr);
}
