#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void clear_memory(char *ptr) {
    // Should be flagged: sizeof() on a pointer
    memset(ptr, 0, sizeof(ptr)); // expect: CGULL-029
}

int main() {
    char *dyn_buf = (char *)malloc(256);
    if (!dyn_buf) return 1;

    // Should be flagged
    int len = sizeof(dyn_buf); // expect: CGULL-029
    printf("Length: %d\n", len);

    // Should NOT be flagged: sizeof on array
    char local_buf[256];
    memset(local_buf, 0, sizeof(local_buf));

    // Should NOT be flagged: sizeof on dereferenced pointer
    memset(dyn_buf, 0, sizeof(*dyn_buf) * 256);

    free(dyn_buf);
    return 0;
}
