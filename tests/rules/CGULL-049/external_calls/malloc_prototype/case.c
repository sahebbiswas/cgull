void *malloc(size_t);
void signed_char_direct(signed char input, char *dst, const char *src) {
    signed char n = input;
    malloc(n); // expect: CGULL-049
}
void signed_char_alias(signed char input, char *dst, const char *src) {
    signed char n = input;
    signed char alias = n;
    malloc(alias); // expect: CGULL-049
}
void signed_char_guard(signed char input, char *dst, const char *src) {
    signed char n = input;
    if (n < 0) return;
    malloc(n);
}
void signed_char_partial_guard(signed char input, char *dst, const char *src) {
    signed char n = input;
    if (n > 100) return;
    malloc(n); // expect: CGULL-049
}
void signed_char_stale_guard(signed char input, char *dst, const char *src) {
    signed char n = input;
    if (n < 0) return;
    n = input;
    malloc(n); // expect: CGULL-049
}
void signed_char_constant(signed char input, char *dst, const char *src) {
    signed char n = input;
    n = 10;
    malloc(n);
}
void signed_char_cast(signed char input, char *dst, const char *src) {
    signed char n = input;
    malloc((size_t)n); // expect: CGULL-049
}
void int_direct(int input, char *dst, const char *src) {
    int n = input;
    malloc(n); // expect: CGULL-049
}
void int_alias(int input, char *dst, const char *src) {
    int n = input;
    int alias = n;
    malloc(alias); // expect: CGULL-049
}
void int_guard(int input, char *dst, const char *src) {
    int n = input;
    if (n < 0) return;
    malloc(n);
}
void int_partial_guard(int input, char *dst, const char *src) {
    int n = input;
    if (n > 100) return;
    malloc(n); // expect: CGULL-049
}
void int_stale_guard(int input, char *dst, const char *src) {
    int n = input;
    if (n < 0) return;
    n = input;
    malloc(n); // expect: CGULL-049
}
void int_constant(int input, char *dst, const char *src) {
    int n = input;
    n = 10;
    malloc(n);
}
void int_cast(int input, char *dst, const char *src) {
    int n = input;
    malloc((size_t)n); // expect: CGULL-049
}
