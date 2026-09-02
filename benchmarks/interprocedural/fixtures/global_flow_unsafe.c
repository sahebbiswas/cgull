int system(const char *command);

static const char *global_command;

static void run_global_command(void) {
    system(global_command);
}

void global_flow_unsafe(const char *input) {
    global_command = input;
    run_global_command();
}
