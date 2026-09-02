#include <stdlib.h>

void CWE401_Memory_Leak__01_baseline_bad(void)
{
    int *ptr = (int *)malloc(sizeof(int));
    if (ptr == NULL) {
        return;
    }
    *ptr = 1;
}

void CWE401_Memory_Leak__01_baseline_good(void)
{
    int *ptr = (int *)malloc(sizeof(int));
    if (ptr == NULL) {
        return;
    }
    *ptr = 1;
    free(ptr);
}
