#include <unistd.h>
#include <stdio.h>

void vulnerable_jail(void) {
    chroot("/var/jail"); // expect: CGULL-039
}

void safe_jail(void) {
    chroot("/var/jail");
    chdir("/");
}

void safe_jail2(void) {
    if (chroot("/var/jail") == 0) {
        chdir("/");
    }
}
