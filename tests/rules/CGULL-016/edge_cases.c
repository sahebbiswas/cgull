/* CGULL-016 Edge Cases Test Suite */

int boot_secure_check(int valid) { // expect: CGULL-016
    if (valid) {
        return true;
    }
    return false;
}

int check_version(int version) {
    return version == 1 ? 1 : 0;
}
