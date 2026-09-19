int isspace(int c);
unsigned long strlen(const char *s);
void use(int c);
void guarded(char *base) {
    char *p = base + strlen(base);
    while (p > base && isspace((unsigned char)*--p)) ;
}
void single_postfix(char *base) {
    char *p = base;
    use(*p--);
}
void unrelated(char *p) {
    use(*--p);
}
