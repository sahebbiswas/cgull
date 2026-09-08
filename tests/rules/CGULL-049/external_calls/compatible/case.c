void *malloc(size_t);
void *malloc(size_t size);
void caller(int n) {
    malloc(n); // expect: CGULL-049
}
