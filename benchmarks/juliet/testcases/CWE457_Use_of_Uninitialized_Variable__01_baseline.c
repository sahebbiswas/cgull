#include <stdio.h>
#include <stdlib.h>

void CWE457_Use_of_Uninitialized_Variable__01_baseline_bad(void) {
    int *ptr;
    *ptr = 10;
}

void CWE457_Use_of_Uninitialized_Variable__01_baseline_good(void) {
    int val = 5;
    int *ptr = &val;
    *ptr = 10;
}
