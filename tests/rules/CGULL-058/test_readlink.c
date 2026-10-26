#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void safe_readlink() {
    char buf[128];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
    }
    printf("%s", buf);
}

void unsafe_readlink() {
    char buf[128];
    readlink("/proc/self/exe", buf, sizeof(buf)); // expect: CGULL-058
    printf("%s", buf);
}

void unsafe_readlink_no_check() {
    char buf[128];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)); // expect: CGULL-058
    printf("%s", buf);
}
