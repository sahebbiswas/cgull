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

int vulnerable_literal_zero() {
    return 100 / 0; // expect: CGULL-034
}

int vulnerable_literal_hex_zero() {
    return 100 % 0x0; // expect: CGULL-034
}

int safe_early_return(int x) {
    if (x == 0) return 0;
    return 100 / x;
}

int safe_single_line(int x) {
    if (x != 0) return 100 / x;
    return 0;
}

int vulnerable_compound(int y) {
    return 100 / (y + 1); // expect: CGULL-034
}

int safe_assign(int w) {
    int res = 0;
    if (w != 0) {
        res = 100 / w;
    }
    return res;
}

int safe_constant_assignment(void) {
    int data = 7;
    return 100 / data;
}

int safe_negative_constant_assignment(void) {
    int data = -7;
    return 100 % data;
}

int vulnerable_zero_assignment(void) {
    int data = 0;
    return 100 / data; // expect: CGULL-034
}

int vulnerable_unknown_reassignment(int input) {
    int data = 7;
    data = input;
    return 100 / data; // expect: CGULL-034
}

int safe_all_branches_nonzero(int flag) {
    int data;
    if (flag) {
        data = 7;
    } else {
        data = -3;
    }
    return 100 / data;
}

int vulnerable_one_branch_unknown(int flag, int input) {
    int data;
    if (flag) {
        data = 7;
    } else {
        data = input;
    }
    return 100 / data; // expect: CGULL-034
}
