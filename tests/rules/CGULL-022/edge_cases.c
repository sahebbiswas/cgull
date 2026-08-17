/* CGULL-022 Edge Cases Test Suite */
#include <stdlib.h>
#include <stdio.h>

/* Access after free pattern */
void test_edge_access_after_free(char *ptr) {
    free(ptr);
    printf("%s", ptr); // expect: CGULL-022
}
