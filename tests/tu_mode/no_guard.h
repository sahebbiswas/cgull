/* Missing inclusion guard header */
#include <stdio.h> // expect: CGULL-045

static inline void helper_func(void) {
    printf("helper\n");
}
