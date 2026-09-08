void external(unsigned int, unsigned int);
void caller(int n, int m) {
    external((unsigned int)n, m); // expect: CGULL-049
}
