#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void clear_memory(char *ptr) {
    // Should be flagged: sizeof() on a pointer
    memset(ptr, 0, sizeof(ptr)); // expect: CGULL-029
}

void test_sizeof_on_array_param(char dest[20]) {
    // Should be flagged: sizeof() on an array parameter which decays to a pointer
    memset(dest, 0, sizeof(dest)); // expect: CGULL-029
}

int global_param = 42;

void test_array_param_same_name_as_global(char global_param[20]) {
    // Should be flagged: parameter shadows non-pointer global and decays to pointer
    memset(global_param, 0, sizeof(global_param)); // expect: CGULL-029
}

void test_array_param_same_name_as_local_in_inner_block(char shadow_local[20]) {
    // Should be flagged: parameter is active in this scope
    memset(shadow_local, 0, sizeof(shadow_local)); // expect: CGULL-029

    {
        int shadow_local = 10;
        // Should NOT be flagged: local non-pointer variable is in scope here
        memset(&shadow_local, 0, sizeof(shadow_local));
    }

    // Should be flagged: parameter is active again after inner block exits
    memset(shadow_local, 0, sizeof(shadow_local)); // expect: CGULL-029
}

char *global_ptr_buf;

void test_global_pointer(void) {
    // Should be flagged: sizeof on a global pointer
    memset(global_ptr_buf, 0, sizeof(global_ptr_buf)); // expect: CGULL-029
}

void test_global_pointer_shadowed_by_param(int global_ptr_buf) {
    // Should NOT be flagged: non-pointer parameter shadows global pointer
    int sz = sizeof(global_ptr_buf);
    (void)sz;
}

char global_fixed_arr[100];

void test_global_array(void) {
    // Should NOT be flagged: global array has compile-time size, not a pointer
    memset(global_fixed_arr, 0, sizeof(global_fixed_arr));
}

int main() {
    char *dyn_buf = (char *)malloc(256);
    if (!dyn_buf) return 1;

    // Should be flagged
    int len = sizeof(dyn_buf); // expect: CGULL-029
    printf("Length: %d\n", len);

    // Should NOT be flagged: sizeof on array
    char local_buf[256];
    memset(local_buf, 0, sizeof(local_buf));

    // Should NOT be flagged: sizeof on dereferenced pointer
    memset(dyn_buf, 0, sizeof(*dyn_buf) * 256);

    free(dyn_buf);
    return 0;
}
