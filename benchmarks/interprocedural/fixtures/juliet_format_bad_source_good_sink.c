/* Reduced Juliet-style CWE-134 BadSource/GoodSink variant. */
int printf(const char *format, ...);

static const char *bad_source(const char *input) {
    return input;
}

static void good_sink(const char *data) {
    printf("%s", data);
}

void juliet_format_bad_source_good_sink(const char *input) {
    good_sink(bad_source(input));
}
