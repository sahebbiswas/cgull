void boundaries(int n) {
    int a[10];
    int *p = a + 3;
    int *start = p - 3;
    int *end = &p[7];
    int v = end[-1];
    int *unknown = p + n;
}
void joined(int n) {
    char a[10];
    char *p;
    if (n) p = a; else p = a + 8;
    p += 3;
}
