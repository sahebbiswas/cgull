#include <stdio.h>
#include <stdlib.h>

void CWE457_Use_of_Uninitialized_Variable__05_switch_bad(void) {
    int *ptr;
    switch (6) {
        case 6:
            *ptr = 10;
            break;
        default:
            break;
    }
}

void CWE457_Use_of_Uninitialized_Variable__05_switch_good(void) {
    int val = 5;
    int *ptr = &val;
    switch (6) {
        case 6:
            *ptr = 10;
            break;
        default:
            break;
    }
}
