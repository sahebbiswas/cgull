void caller(int n) {
    void *(*malloc)(size_t) = 0;
    malloc(n);
}
