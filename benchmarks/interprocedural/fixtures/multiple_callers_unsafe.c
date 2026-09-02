int system(const char *command);

static void run_command(const char *command) {
    system(command);
}

void trusted_caller(void) {
    run_command("true");
}

void multiple_callers_unsafe(const char *input) {
    run_command(input);
}
