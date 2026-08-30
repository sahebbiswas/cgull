#include <stdio.h>
#include <stdlib.h>

void CWE457_Use_of_Uninitialized_Variable__04_loops_bad(void) {
    int *ptr;
    for (int i = 0; i < 1; i++) {
        *ptr = 10;
    }
}

void CWE457_Use_of_Uninitialized_Variable__04_loops_good(void) {
    int val = 5;
    int *ptr = &val;
    for (int i = 0; i < 1; i++) {
        *ptr = 10;
    }
}
