int isspace(int c);
unsigned long strlen(const char *s);
void use(int c);
char *trim(char *base) {
    if (!base) return base;
    char *p = base + strlen(base);
    while (isspace(*--p)) ; // expect: CGULL-056
    return base;
}
void separated(char *base) {
    char *p = base;
    p--;
    *p = 0; // expect: CGULL-056
}
void postfix(char *base, int n) {
    char *p = base + 2;
    for (; n; ) {
        use(*p--); // expect: CGULL-056
    }
}
