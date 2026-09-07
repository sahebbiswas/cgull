int valid_range(void *, unsigned long);
void positive(char *p, char *dst) {
    if (!valid_range(p, 16)) return;
    int v = *(int *)(p + 14); // expect: CGULL-051
    char *q = p - 4;
    char x = *q; // expect: CGULL-051
    memcpy(dst, p + 14, 4); // expect: CGULL-051
}
