/* CGULL-032 Behavioral Test Suite - Realloc-Overwrite Memory Leak */
#include <stdlib.h>
#include <stdio.h>

/* Positive Test Case 1: Simple realloc overwrite */
void test_simple_overwrite(void) {
    char *ptr = (char *)malloc(100);
    if (!ptr) return;

    ptr = realloc(ptr, 200); // expect: CGULL-032
    if (!ptr) {
        printf("Realloc failed!\n");
        return;
    }
    free(ptr);
}

/* Positive Test Case 2: Realloc overwrite with explicit type cast */
void test_cast_overwrite(void) {
    int *arr = (int *)malloc(10 * sizeof(int));
    if (!arr) return;

    arr = (int *)realloc(arr, 50 * sizeof(int)); // expect: CGULL-032
    if (!arr) return;
    free(arr);
}

/* Positive Test Case 3: Struct member realloc overwrite */
struct Buffer {
    char *data;
};

void test_struct_member_overwrite(struct Buffer *b) {
    b->data = realloc(b->data, 512); // expect: CGULL-032
    if (!b->data) return;
}

/* Negative Test Case 1: Safe realloc with temporary pointer */
void test_safe_realloc_tmp(void) {
    char *ptr = (char *)malloc(100);
    if (!ptr) return;

    char *tmp = (char *)realloc(ptr, 200);
    if (!tmp) {
        free(ptr); // Original block still valid!
        return;
    }
    ptr = tmp;
    free(ptr);
}

/* Negative Test Case 2: Realloc assigning to a different pointer */
void test_different_pointer(char *orig) {
    char *new_ptr = realloc(orig, 300);
    if (!new_ptr) {
        /* orig is still valid */
        free(orig);
        return;
    }
    free(new_ptr);
}
