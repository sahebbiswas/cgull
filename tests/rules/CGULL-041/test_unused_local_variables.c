#include <stdio.h>

int compute(int x) {
    int unused_local = 42;          // expect: CGULL-041

    switch (x) {
        case 1: {
            int unused_case_var = 7;   // expect: CGULL-041
            return 1;
        }
        default:
            return 0;
    }
}

void loop_example(int n) {
    int i = 0;
    do {
        int unused_do_var = i * 2;   // expect: CGULL-041
        i++;
    } while (i < n);
}

void address_taken_example(void) {
    int val = 0;
    int *p = &val;
    *p = 10;
}

void void_cast_example(void) {
    int silenced_var = 100;
    (void)silenced_var;
}

void shadowed_scope_example(void) {
    int outer_unused = 1; // expect: CGULL-041
    {
        int inner_used = 2;
        int inner_unused = 3; // expect: CGULL-041
        printf("%d\n", inner_used);
    }
}
