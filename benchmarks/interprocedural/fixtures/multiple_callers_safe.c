int system(const char *command);

static void run_command(const char *command) {
    system(command);
}

void first_trusted_caller(void) {
    run_command("true");
}

void multiple_callers_safe(void) {
    run_command("false");
}
