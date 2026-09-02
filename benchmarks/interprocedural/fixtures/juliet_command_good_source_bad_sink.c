/* Reduced Juliet-style CWE-78 GoodSource/BadSink variant. */
int system(const char *command);

static const char *good_source(void) {
    return "true";
}

static void bad_sink(const char *command) {
    system(command);
}

void juliet_command_good_source_bad_sink(void) {
    bad_sink(good_source());
}
