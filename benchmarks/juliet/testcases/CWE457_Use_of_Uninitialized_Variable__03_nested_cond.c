#include <stdio.h>
#include <stdlib.h>

void CWE457_Use_of_Uninitialized_Variable__03_nested_cond_bad(void) {
    int *ptr;
    if (1) {
        if (1) {
            *ptr = 10;
        }
    }
}

void CWE457_Use_of_Uninitialized_Variable__03_nested_cond_good(void) {
    int val = 5;
    int *ptr = &val;
    if (1) {
        if (1) {
            *ptr = 10;
        }
    }
}
