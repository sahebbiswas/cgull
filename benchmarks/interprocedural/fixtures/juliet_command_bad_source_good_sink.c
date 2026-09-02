/* Reduced Juliet-style CWE-78 BadSource/GoodSink variant. */
int system(const char *command);

static const char *bad_source(const char *input) {
    return input;
}

static void good_sink(const char *command) {
    (void)command;
    system("true");
}

void juliet_command_bad_source_good_sink(const char *input) {
    good_sink(bad_source(input));
}
