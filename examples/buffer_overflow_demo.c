/**
 * Buffer Overflow & Memory Lifecycle Demo for C-GULL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct UserSession {
    int user_id;
    char username[32];
};

void vulnerable_stack_overflow(char *untrusted_str) {
    char stack_dest[16];
    // Insecure legacy string copy without length bounds
    strcpy(stack_dest, untrusted_str);
}

void use_after_free_demo(void) {
    struct UserSession *session = (struct UserSession *)malloc(sizeof(struct UserSession));
    if (session == NULL) return;

    session->user_id = 42;
    strcpy(session->username, "admin");

    // Free memory
    free(session);

    // Dangerous Use-After-Free access
    printf("Freed User ID: %d\n", session->user_id);
}

void arithmetic_overflow_demo(int count) {
    // Unchecked multiplication can wrap around to 0 or small number
    int *array = (int *)malloc(count * sizeof(int));
    if (array != NULL) {
        array[0] = 1;
        free(array);
    }
}
