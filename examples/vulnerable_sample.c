/**
 * Vulnerable C Sample for C-GULL Security Audit
 * Demonstrates high and medium severity security vulnerabilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// CGULL-019: Extraneous or Missing void in Parameter Lists
int init_system() {
    return 0;
}

// CGULL-016: Single-Point-of-Failure Control Flow (Boolean return in auth)
int check_admin_token(const char *provided_token, const char *master_token) {
    // CGULL-005: Non-Constant Time Memory Comparison (Timing Attack)
    if (memcmp(provided_token, master_token, 32) == 0) {
        return 1; // Single bit return
    }
    return 0;
}

void process_client_request(char *user_input, int packet_len) {
    // CGULL-021: Uninitialized Pointer
    char *session_key;
    
    // CGULL-010: Variable Length Array (VLA stack exhaustion)
    char temp_stack_buf[packet_len];

    // CGULL-001: Banned Functions (strcpy, gets, sprintf)
    char local_buffer[64];
    strcpy(local_buffer, user_input);

    // CGULL-002: Format String Vulnerability
    printf(user_input);

    // CGULL-003: Unchecked Dynamic Allocation
    char *heap_packet = (char *)malloc(1024);
    heap_packet[0] = 'H'; // Dereference without NULL check

    // CGULL-012: Unsafe Integer Conversion
    int timeout = atoi(user_input);

    // CGULL-013: Naked Control Flow Statement
    if (timeout > 100)
        printf("Timeout exceeded\n");

    // CGULL-008: Unsafe Sensitive Memory Clearing (Dead Store Elimination)
    char secret_key[32];
    memset(secret_key, 0, sizeof(secret_key));
    return;
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        process_client_request(argv[1], 128);
    }
    return 0;
}
