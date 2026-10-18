#define _GNU_SOURCE
#include <unistd.h>

void safe_drops() {
    if (setuid(1000) != 0) return;
    int res = setgid(1000);
    if (res < 0) return;
    while (seteuid(1000) != 0) {}
}

void unsafe_drops(int flag) {
    setuid(1000); // expect: CGULL-057
    (void)setgid(1000); // expect: CGULL-057
    int rc = 0; setuid(1000); // expect: CGULL-057
    if (flag) setegid(1000); // expect: CGULL-057
    while (flag) setresuid(1000, 1000, 1000); // expect: CGULL-057
    if (flag) { rc = 1; } else setresgid(1000, 1000, 1000); // expect: CGULL-057
    for (setuid(1000); flag; flag--) {} // expect: CGULL-057
    switch (flag) {
    case -1: setgid(1000); break; // expect: CGULL-057
    default: break;
    }
    if (flag)
        seteuid(1000); // expect: CGULL-057
}
