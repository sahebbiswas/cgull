#include <stdlib.h>

void CWE401_Memory_Leak__02_ifelse_bad(void)
{
    int flag = 1;
    int *ptr = (int *)malloc(sizeof(int));
    if (ptr == NULL) {
        return;
    }
    if (flag) {
        *ptr = 1;
    } else {
        *ptr = 2;
    }
}

void CWE401_Memory_Leak__02_ifelse_good(void)
{
    int flag = 1;
    int *ptr = (int *)malloc(sizeof(int));
    if (ptr == NULL) {
        return;
    }
    if (flag) {
        *ptr = 1;
    } else {
        *ptr = 2;
    }
    free(ptr);
}
