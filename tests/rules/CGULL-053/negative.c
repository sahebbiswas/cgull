void same(void) {
    int a[8];
    long d = &a[4] - &a[2];
    uintptr_t u = (uintptr_t)a;
    u += 4;
    *(int *)u = 0;
}
