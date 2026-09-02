int printf(const char *format, ...);

static void print_wrapper(const char *format) {
    printf(format);
}

void direct_wrapper_unsafe(const char *input) {
    print_wrapper(input);
}
