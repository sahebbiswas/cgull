#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printLine(const char *str) {
    if (str) printf("%s\n", str);
}

// NIST Juliet CWE401 pattern: memory leak (bad)
void CWE401_Memory_Leak__char_malloc_01_bad(void) {
    char *data;
    data = NULL;
    data = (char *)malloc(100 * sizeof(char)); // expect: CGULL-036
    if (data == NULL) {
        exit(-1);
    }
    strcpy(data, "A String");
    printLine(data);
    /* POTENTIAL FLAW: No deallocation */
}

// NIST Juliet CWE401 pattern: safe deallocation (good)
void CWE401_Memory_Leak__char_malloc_01_good(void) {
    char *data;
    data = NULL;
    data = (char *)malloc(100 * sizeof(char));
    if (data == NULL) {
        exit(-1);
    }
    strcpy(data, "A String");
    printLine(data);
    free(data);
}

// Ownership transfer via return value (good)
char* allocate_string(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return NULL;
    strcpy(buf, "test");
    return buf;
}

// Memory leak on early return branch (bad)
void early_return_leak(int flag) {
    char *ptr = (char *)malloc(128); // expect: CGULL-036
    if (!ptr) return;
    if (flag) {
        return; // Leaks ptr on early return
    }
    free(ptr);
}

// Overwritten allocation leak (bad)
void f(void){ 
    char* p = malloc(10); // expect: CGULL-036
    p = malloc(20); 
    free(p); 
}
