#include <stdio.h>
#include <stdlib.h>

static void CWE457_09_bad_sink(int *ptr) {
    *ptr = 10;
}

void CWE457_Use_of_Uninitialized_Variable__09_interprocedural_bad(void) {
    int *ptr;
    CWE457_09_bad_sink(ptr);
}

static void CWE457_09_good_sink(int *ptr) {
    *ptr = 10;
}

void CWE457_Use_of_Uninitialized_Variable__09_interprocedural_good(void) {
    int val = 5;
    int *ptr = &val;
    CWE457_09_good_sink(ptr);
}
