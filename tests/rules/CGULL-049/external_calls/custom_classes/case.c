void external(int, unsigned int, int, unsigned char);
void unsafe(signed char a, int b, unsigned int c, unsigned int d) {
    external(a, b, c, d); // expect: CGULL-049
}
void safe(signed char a, int b, unsigned int c, unsigned int d) {
    if (a < 0 || b < 0 || c > 2147483647U || d > 255U) return;
    external(a, b, c, d);
}
