#include <stdio.h>

int global_counter = 0;
int global_flag = 1;

void param_shadows_global(int global_counter) { // expect: CGULL-043
    printf("%d\n", global_counter);
}

void local_shadows_param(int limit) {
    int limit = 100; // expect: CGULL-043
    printf("%d\n", limit);
}

void local_shadows_global(void) {
    int global_flag = 0; // expect: CGULL-043
    printf("%d\n", global_flag);
}

void inner_shadows_outer_block(void) {
    int index = 1;
    if (index > 0) {
        int index = 2; // expect: CGULL-043
        printf("%d\n", index);
    }
}

void for_loop_shadows_outer(void) {
    int i = 0;
    for (int i = 0; i < 5; i++) { // expect: CGULL-043
        printf("%d\n", i);
    }
}

void clean_no_shadowing(int param_val) {
    int local_var = 10;
    if (param_val > 0) {
        int inner_a = 1;
        printf("%d\n", local_var + inner_a);
    } else {
        int inner_b = 2;
        printf("%d\n", local_var + inner_b);
    }
}
