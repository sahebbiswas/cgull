#include <stdio.h>

int vulnerable_division(int y) {
    return 100 / y; // expect: CGULL-034
}

int vulnerable_modulo(int z) {
    return 100 % z; // expect: CGULL-034
}

int safe_division(int y) {
    if (y != 0) {
        return 100 / y;
    }
    return 0;
}

int safe_modulo(int z) {
    if (z > 0) {
        return 100 % z;
    }
    return 0;
}

int safe_literal() {
    return 100 / 2;
}

int safe_early_return(int x) {
    if (x == 0) return 0;
    return 100 / x;
}

int safe_assign(int w) {
    int res = 0;
    if (w != 0) {
        res = 100 / w;
    }
    return res;
}
