#ifndef VULNERABLE_H
#define VULNERABLE_H

#include <stdio.h>

static inline void unsafe_read(char *buf) {
    gets(buf); // expect: CGULL-001
}

#endif
