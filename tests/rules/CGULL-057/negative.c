#include <unistd.h>

void handle_status(int);
void report(int, int);

extern int setuid(uid_t uid);

#define DROP_PRIVS() setuid(0)

struct ops { int (*setuid)(int); };

void safe_drops(int flag, struct ops *o) {
    if (setuid(1000) != 0) return;
    int res = setgid(1000);
    if (res < 0) return;
    while (seteuid(1000) != 0) {}
    handle_status(setuid(1000));
    report(1, setgid(1000));
    handle_status(report(0, seteuid(1000)));
    for (flag = 0; setuid(1000); flag++) {}
    flag = flag ? setegid(1000) : 0;
    setuid(1000) || handle_status(1);
    if (flag && setresuid(1000, 1000, 1000) != 0) return;
    res = (setresgid(1000, 1000, 1000));
    o->setuid(1000);
    res =
        setuid(1000);
    handle_status(flag,
        setuid(1000));
    if (flag &&
        setgid(1000))
        return;
}

int returns_status(void) {
    return setuid(1000);
}

int returns_parenthesized(void) {
    return (setgid(1000));
}

int uses_macro(void) {
    return DROP_PRIVS();
}
