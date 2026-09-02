#include <stdlib.h>

void CWE415_Double_Free__02_ifelse_bad(void)
{
    int flag = 1;
    int *ptr = (int *)malloc(sizeof(int));
    if (ptr == NULL) {
        return;
    }
    free(ptr);
    if (flag) {
        free(ptr);
    } else {
        free(ptr);
    }
}

void CWE415_Double_Free__02_ifelse_good(void)
{
    int flag = 1;
    int *ptr = (int *)malloc(sizeof(int));
    if (ptr == NULL) {
        return;
    }
    if (flag) {
        free(ptr);
    } else {
        free(ptr);
    }
}
