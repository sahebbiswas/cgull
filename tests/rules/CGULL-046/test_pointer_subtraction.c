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

// New tests for nested arithmetic and UnaryOp &
void test_nested_arithmetic(int *p1, int *p2) {
    char *dest = (char *)malloc(1024);
    if (!dest) return;

    // BAD: Nested unscaled subtraction
    memcpy(dest, p1, (p2 - p1) + 1); // expect: CGULL-046
    
    // BAD: Unscaled subtraction multiplied by a non-sizeof constant
    memcpy(dest, p1, (p2 - p1) * 2); // expect: CGULL-046

    // GOOD: Scaled correctly inside a complex expression
    memcpy(dest, p1, ((p2 - p1) * sizeof(int)) + 1);

    free(dest);
}

struct MyStruct {
    int *ptr;
};

void test_struct_and_array(struct MyStruct s1, struct MyStruct s2, int **arr) {
    // BAD: Struct references
    int *buf = malloc(s2.ptr - s1.ptr); // expect: CGULL-046

    // BAD: Array references
    int *buf2 = malloc(arr[1] - arr[0]); // expect: CGULL-046
}

typedef char my_byte_t;

void test_typedef_alias(my_byte_t *b1, my_byte_t *b2) {
    // GOOD: Subtraction of byte pointers (aliased) yields byte count
    int *buf = malloc(b2 - b1);
}

void test_unary_op_address(int *arr) {
    // BAD: Subtracting pointers to int (yielding number of ints)
    int *buf = malloc(&arr[5] - &arr[0]); // expect: CGULL-046
}

int *global_ptr;

void test_scoping(char *global_ptr) {
    char *p;
    // GOOD: Should resolve to the parameter (char *) instead of the global (int *)
    int *buf = malloc(global_ptr - p);
}
