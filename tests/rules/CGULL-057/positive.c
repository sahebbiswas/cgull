#include <unistd.h>

void safe_drops() {
    if (setuid(1000) != 0) return;
    int res = setgid(1000);
    if (res < 0) return;
    while (seteuid(1000) != 0) {}
}

void unsafe_drops() {
    setuid(1000); // expect: CGULL-057
    (void)setgid(1000); // expect: CGULL-057
}
