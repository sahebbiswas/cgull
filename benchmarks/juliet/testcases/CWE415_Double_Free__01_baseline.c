#include <stdlib.h>

void CWE415_Double_Free__01_baseline_bad(void)
{
    int *ptr = (int *)malloc(sizeof(int));
    if (ptr == NULL) {
        return;
    }
    free(ptr);
    free(ptr);
}

void CWE415_Double_Free__01_baseline_good(void)
{
    int *ptr = (int *)malloc(sizeof(int));
    if (ptr == NULL) {
        return;
    }
    free(ptr);
}
