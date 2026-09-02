int printf(const char *format, ...);

static void print_wrapper(const char *format) {
    printf(format);
}

void direct_wrapper_safe(void) {
    print_wrapper("fixed text");
}
