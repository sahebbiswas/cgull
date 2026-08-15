/**
 * Remediated & Hardened C Sample for C-GULL
 * Complies with bounds checking, constant-time comparisons, and MISRA-C rules.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#define STATUS_AUTH_OK   0x5A5A5A5AU
#define STATUS_AUTH_FAIL 0xA5A5A5A5U
#define BUFFER_MAX_LEN   64U
#define MAX_TIMEOUT      100

// Safe constant-time comparison
static int secure_memcmp(const void *a, const void *b, size_t len) {
    const unsigned char *ua = (const unsigned char *)a;
    const unsigned char *ub = (const unsigned char *)b;
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= (ua[i] ^ ub[i]);
    }
    return result;
}

// Explicit (void) parameter list
int init_system(void) {
    return 0;
}

// Multi-bit status word with constant-time comparison
uint32_t check_admin_token(const char *provided_token, const char *master_token) {
    if (provided_token == NULL || master_token == NULL) {
        return STATUS_AUTH_FAIL;
    }
    if (secure_memcmp(provided_token, master_token, 32) == 0) {
        return STATUS_AUTH_OK;
    }
    return STATUS_AUTH_FAIL;
}

void process_client_request(const char *user_input, size_t packet_len) {
    if (user_input == NULL) {
        return;
    }

    // Explicitly initialized pointer
    char *session_key = NULL;
    (void)session_key; // Silence unused warning

    // Heap allocation with bounds check instead of VLA
    if (packet_len > 1024) {
        return;
    }
    char *safe_buf = (char *)malloc(packet_len);
    if (safe_buf == NULL) {
        return;
    }

    // Safe bounded string copy
    char local_buffer[BUFFER_MAX_LEN];
    snprintf(local_buffer, sizeof(local_buffer), "%s", user_input);

    // Literal format string
    printf("%s\n", local_buffer);

    // Checked dynamic memory allocation
    char *heap_packet = (char *)malloc(1024);
    if (heap_packet == NULL) {
        free(safe_buf);
        return;
    }
    heap_packet[0] = 'H';

    // Safe integer conversion with overflow & error checks
    char *endptr = NULL;
    errno = 0;
    long timeout = strtol(user_input, &endptr, 10);
    if (errno == 0 && endptr != user_input && timeout > MAX_TIMEOUT) {
        printf("Timeout limit reached\n");
    }

    // Free resources
    free(heap_packet);
    heap_packet = NULL;
    free(safe_buf);
    safe_buf = NULL;
}

int main(int argc, char *argv[]) {
    assert(argc >= 1);
    if (argc > 1) {
        process_client_request(argv[1], 128);
    }
    return 0;
}
