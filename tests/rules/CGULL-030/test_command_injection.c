#include <stdlib.h>
#include <stdio.h>

char* build_cmd(char *prefix, char *input) {
    return "cmd";
}

int system(const char *command); // Declaration shouldn't flag
FILE *popen(const char *command, const char *mode); // Declaration shouldn't flag

void vulnerable_system(char *user_input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ls %s", user_input);
    system(cmd); // expect: CGULL-030
}

void vulnerable_system_multiline(char *user_input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ls %s", user_input);
    system( // expect: CGULL-030
        cmd
    );
}

void vulnerable_system_nested(char *user_input) {
    system(build_cmd("prefix", user_input)); // expect: CGULL-030
}

void vulnerable_popen(char *user_input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cat %s", user_input);
    FILE *fp = popen(cmd, "r"); // expect: CGULL-030
    if (fp) pclose(fp);
}

void safe_system() {
    system("ls -la");
}

void safe_system_u8() {
    system(u8"ls -la");
}

void safe_system_L() {
    system(L"ls -la");
}

void safe_popen() {
    FILE *fp = popen("cat /etc/passwd", "r");
    if (fp) pclose(fp);
}
