void *memcpy(void *, const void *, size_t);
void signed_char_direct(signed char input, char *dst, const char *src) {
    signed char n = input;
    memcpy(dst, src, n); // expect: CGULL-049
}
void signed_char_alias(signed char input, char *dst, const char *src) {
    signed char n = input;
    signed char alias = n;
    memcpy(dst, src, alias); // expect: CGULL-049
}
void signed_char_guard(signed char input, char *dst, const char *src) {
    signed char n = input;
    if (n < 0) return;
    memcpy(dst, src, n);
}
void signed_char_partial_guard(signed char input, char *dst, const char *src) {
    signed char n = input;
    if (n > 100) return;
    memcpy(dst, src, n); // expect: CGULL-049
}
void signed_char_stale_guard(signed char input, char *dst, const char *src) {
    signed char n = input;
    if (n < 0) return;
    n = input;
    memcpy(dst, src, n); // expect: CGULL-049
}
void signed_char_constant(signed char input, char *dst, const char *src) {
    signed char n = input;
    n = 10;
    memcpy(dst, src, n);
}
void signed_char_cast(signed char input, char *dst, const char *src) {
    signed char n = input;
    memcpy(dst, src, (size_t)n); // expect: CGULL-049
}
void int_direct(int input, char *dst, const char *src) {
    int n = input;
    memcpy(dst, src, n); // expect: CGULL-049
}
void int_alias(int input, char *dst, const char *src) {
    int n = input;
    int alias = n;
    memcpy(dst, src, alias); // expect: CGULL-049
}
void int_guard(int input, char *dst, const char *src) {
    int n = input;
    if (n < 0) return;
    memcpy(dst, src, n);
}
void int_partial_guard(int input, char *dst, const char *src) {
    int n = input;
    if (n > 100) return;
    memcpy(dst, src, n); // expect: CGULL-049
}
void int_stale_guard(int input, char *dst, const char *src) {
    int n = input;
    if (n < 0) return;
    n = input;
    memcpy(dst, src, n); // expect: CGULL-049
}
void int_constant(int input, char *dst, const char *src) {
    int n = input;
    n = 10;
    memcpy(dst, src, n);
}
void int_cast(int input, char *dst, const char *src) {
    int n = input;
    memcpy(dst, src, (size_t)n); // expect: CGULL-049
}
