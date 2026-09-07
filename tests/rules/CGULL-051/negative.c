int valid_range(void *, unsigned long);
void negative(char *p, char *dst) {
    if (!valid_range(p, 16)) return;
    int v = *(int *)(p + 12);
    char *q = p - 4;
    memcpy(dst, p + 12, 4);
}
void unchecked(char *p) {
    valid_range(p, 16);
    char x = p[-1];
}
