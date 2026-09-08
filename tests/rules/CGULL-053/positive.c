void different(void) {
    int a[8], b[8];
    long d = &a[4] - &b[2]; // expect: CGULL-053
}
void lossy(void) {
    char a[16];
    uintptr_t u = (uintptr_t)a;
    u ^= 4;
    *(char *)u = 0; // expect: CGULL-053
}
