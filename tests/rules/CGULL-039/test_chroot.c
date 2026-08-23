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

void string_literal_safe(void) {
    printf("use chroot()");
}

void chdir_outside_block(void) {
    {
        chroot("/var/jail"); // expect: CGULL-039
    }
    chdir("/");
}

void comment_safe(void) {
    chroot("/var/jail"); // just a comment
    chdir("/");
}
