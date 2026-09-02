int printf(const char *format, ...);

static const char *select_format(void) {
    return "fixed text";
}

void return_propagation_safe(void) {
    printf(select_format());
}
