#include <string.h>

void vulnerable_strncpy(char *input) {
    char buf[10];
    strncpy(buf, input, sizeof(buf)); // expect: CGULL-037
}

void safe_strncpy(char *input) {
    char buf[10];
    strncpy(buf, input, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
}
