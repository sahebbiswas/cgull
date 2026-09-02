int printf(const char *format, ...);

static const char *select_format(const char *input) {
    return input;
}

void return_propagation_unsafe(const char *input) {
    printf(select_format(input));
}
