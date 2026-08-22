#include <stdlib.h>

int* vulnerable_stack_var(void) {
    int x = 10;
    return &x; // expect: CGULL-038
}

char* vulnerable_stack_array(void) {
    char buf[256];
    return buf; // expect: CGULL-038
}

int* safe_static_var(void) {
    static int x = 10;
    return &x;
}

int* safe_heap_var(void) {
    int* ptr = malloc(sizeof(int));
    if (!ptr) return NULL;
    *ptr = 10;
    return ptr;
}

int* vulnerable_param(int x) {
    return &x; // expect: CGULL-038
}

int* vulnerable_cast(void) {
    int x = 10;
    return (int *)&x; // expect: CGULL-038
}
