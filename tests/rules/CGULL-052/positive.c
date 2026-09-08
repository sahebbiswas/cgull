int unsafe(char *p, unsigned long len, char *end) {
    return p + len <= end; // expect: CGULL-052
}
int subtract(char *p, unsigned long len, char *base) {
    return p - len >= base; // expect: CGULL-052
}
