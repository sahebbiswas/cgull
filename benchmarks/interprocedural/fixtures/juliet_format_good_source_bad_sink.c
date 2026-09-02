/* Reduced Juliet-style CWE-134 GoodSource/BadSink variant. */
int printf(const char *format, ...);

static const char *good_source(void) {
    return "fixed text";
}

static void bad_sink(const char *data) {
    printf(data);
}

void juliet_format_good_source_bad_sink(void) {
    bad_sink(good_source());
}
