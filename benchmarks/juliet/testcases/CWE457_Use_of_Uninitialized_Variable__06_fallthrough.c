#include <stdio.h>
#include <stdlib.h>

void CWE457_Use_of_Uninitialized_Variable__06_fallthrough_bad(void) {
    int *ptr;
    switch (6) {
        case 6:
        case 7:
            *ptr = 10;
            break;
        default:
            break;
    }
}

void CWE457_Use_of_Uninitialized_Variable__06_fallthrough_good(void) {
    int val = 5;
    int *ptr = &val;
    switch (6) {
        case 6:
        case 7:
            *ptr = 10;
            break;
        default:
            break;
    }
}
