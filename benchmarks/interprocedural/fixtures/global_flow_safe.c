int system(const char *command);

static const char *global_command = "true";

static void run_global_command(void) {
    system(global_command);
}

void global_flow_safe(void) {
    run_global_command();
}
