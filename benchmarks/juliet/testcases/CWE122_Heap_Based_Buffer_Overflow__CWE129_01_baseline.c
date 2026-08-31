/*
 * Reduced, self-contained Juliet 1.3 CWE-122/CWE-129 bounds fixture.
 * CGULL-007 tracks constant heap allocation capacity for this bounds check.
 */
#include <stdlib.h>

void CWE122_Heap_Based_Buffer_Overflow__CWE129_01_baseline_bad(void) {
    char *data = (char *)malloc(10);
    if (data != NULL) {
        data[10] = 'A';
        free(data);
    }
}

void CWE122_Heap_Based_Buffer_Overflow__CWE129_01_baseline_good(void) {
    char *data = (char *)malloc(10);
    if (data != NULL) {
        data[9] = 'A';
        free(data);
    }
}
