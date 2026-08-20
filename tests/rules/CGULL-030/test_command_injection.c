#include <stdlib.h>
#include <stdio.h>

void vulnerable_system(char *user_input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ls %s", user_input);
    system(cmd); // expect: CGULL-030
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

void safe_popen() {
    FILE *fp = popen("cat /etc/passwd", "r");
    if (fp) pclose(fp);
}
