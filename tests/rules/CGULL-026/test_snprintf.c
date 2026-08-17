#include <stdio.h>
#include <string.h>

void vulnerable_snprintf_offset() {
    char buf[128];
    int offset = 0;

    // Unchecked return value accumulation
    offset += snprintf(buf + offset, sizeof(buf) - offset, "Hello"); // expect: CGULL-026
    offset += snprintf(buf + offset, sizeof(buf) - offset, " World"); // expect: CGULL-026
}

void safe_snprintf_offset() {
    char buf[128];
    int offset = 0;
    int n;

    n = snprintf(buf + offset, sizeof(buf) - offset, "Hello");
    if (n > 0 && n < sizeof(buf) - offset) {
        offset += n;
    }

    n = snprintf(buf + offset, sizeof(buf) - offset, " World");
    if (n > 0 && n < sizeof(buf) - offset) {
        offset += n;
    }
}
