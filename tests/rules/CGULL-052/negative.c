int safe(char *p, unsigned long len, char *end) {
    if (p > end) return 0;
    return len <= (unsigned long)(end - p);
}
