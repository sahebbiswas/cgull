/* Reduced, self-contained Juliet 1.3 CWE-190 allocation-overflow fixture. */
#include <stdint.h>
#include <stdlib.h>

void CWE190_Integer_Overflow__malloc_01_baseline_bad(size_t count) {
    int *data = (int *)malloc(count * sizeof(int));
    free(data);
}

void CWE190_Integer_Overflow__malloc_01_baseline_good(size_t count) {
    if (count > SIZE_MAX / sizeof(int)) {
        return;
    }
    int *data = (int *)malloc(count * sizeof(int));
    free(data);
}
