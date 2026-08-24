#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

void pointer_scaling_vulnerable() {
    int *ptr = (int *)malloc(10 * sizeof(int));
    if (!ptr) return;

    // FLAW: C scales pointer arithmetic automatically.
    // ptr + (5 * sizeof(int)) will actually advance ptr by 5 * 4 * 4 bytes = 80 bytes!
    int *offset_ptr = ptr + (5 * sizeof(int)); // expect: CGULL-040

    // Expect another one
    ptr += 2 * sizeof(int); // expect: CGULL-040

    // This is fine
    int *safe_ptr = ptr + 5;

    // Expect another one (subtraction)
    int *back_ptr = offset_ptr - sizeof(int); // expect: CGULL-040

    int *other_ptr = (int *)malloc(100);
    int *bad_ptr = sizeof(int) * 3 + other_ptr; // expect: CGULL-040

    free(ptr);
}

void pointer_scaling_safe() {
    char *buf = (char *)malloc(1024);
    if (!buf) return;

    // This is technically also doing it, but maybe our rule catches it? Let's check.
    // Actually our rule currently catches ALL pointers except those we filter out.
    // Let's remove expect since we explicitly ignore char* scaling (as sizeof(char) is 1, so it is mathematically safe although ugly).
    char *offset = buf + 10 * sizeof(char);

    free(buf);
}

void pointer_scaling_advanced() {
    wchar_t *p;
    p = p + (2 * sizeof(wchar_t)); // expect: CGULL-040

    char **double_p;
    double_p = double_p + sizeof(char*); // expect: CGULL-040

    // malloc cast tests
    char *char_p = (char*)malloc(10);
    char_p = char_p + 2 * sizeof(char); // Should NOT be flagged

    int *int_p = (int*)malloc(10);
    int_p = int_p + 2 * sizeof(int); // expect: CGULL-040

    // void* single level pointer should not be flagged
    void *void_p = malloc(10);
    void_p = void_p + 2 * sizeof(int); // Should NOT be flagged

    // void** double level pointer SHOULD be flagged
    void **void_pp = (void**)malloc(10);
    void_pp = void_pp + 2 * sizeof(void*); // expect: CGULL-040
}
