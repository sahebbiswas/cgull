#include <stdio.h>
#include <stdlib.h>

void CWE457_Use_of_Uninitialized_Variable__07_break_continue_bad(void) {
    int *ptr;
    while (1) {
        *ptr = 10;
        break;
    }
}

void CWE457_Use_of_Uninitialized_Variable__07_break_continue_good(void) {
    int val = 5;
    int *ptr = &val;
    while (1) {
        *ptr = 10;
        break;
    }
}
