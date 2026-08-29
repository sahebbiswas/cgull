#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void vulnerable_pointer_subtraction(int *p1, int *p2) {
    char *dest = (char *)malloc(1024);
    if (!dest) return;

    // BAD: Pointer subtraction yields number of elements, not bytes.
    memcpy(dest, p1, p2 - p1); // expect: CGULL-046

    // Also bad for malloc
    int *buf = malloc(p2 - p1); // expect: CGULL-046

    free(dest);
    free(buf);
}

void safe_pointer_subtraction(int *p1, int *p2) {
    char *dest = (char *)malloc(1024);
    if (!dest) return;

    // GOOD: Scaled correctly
    memcpy(dest, p1, (p2 - p1) * sizeof(int));

    // GOOD: Scaled correctly via casting to byte pointers first
    memcpy(dest, p1, (char *)p2 - (char *)p1);

    free(dest);
}

void other_types_subtraction(double *start, double *end) {
    // BAD
    memset(start, 0, end - start); // expect: CGULL-046

    // GOOD
    memset(start, 0, (end - start) * sizeof(double));
}
