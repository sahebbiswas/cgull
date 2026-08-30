#include <stdio.h>
#include <stdlib.h>

void CWE457_Use_of_Uninitialized_Variable__08_goto_bad(void) {
    int *ptr;
    goto sink;
sink:
    *ptr = 10;
}

void CWE457_Use_of_Uninitialized_Variable__08_goto_good(void) {
    int val = 5;
    int *ptr = &val;
    goto sink;
sink:
    *ptr = 10;
}
