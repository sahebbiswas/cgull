int valid_range(void *, unsigned long);
void positive(char *p, char *dst) {
    if (!valid_range(p, 16)) return;
    int v = *(int *)(p + 14); // expect: CGULL-051
    char *q = p - 4;
    char x = *q; // expect: CGULL-051
    memcpy(dst, p + 14, 4); // expect: CGULL-051
}
void upper_only(char *p, char *end) {
    if (!valid_range(p, 16)) return;
    if (end - p < 20) return;
    char header = p[-1]; // expect: CGULL-051
}
void stale_lower(char *p, char *base) {
    if (!valid_range(p, 16)) return;
    if (p - base < 4) return;
    base++;
    char header = p[-4]; // expect: CGULL-051
}
