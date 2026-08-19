/* CGULL-028 Insecure PRNG Test Suite */
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/* True Positive: rand() used for security token */
void test_tp_rand_token(void) {
    int token = rand(); // expect: CGULL-028
}

/* True Positive: multiline assignment for session token */
void test_tp_multiline_token(void) {
    uint32_t session_token =
        rand(); // expect: CGULL-028
    (void)session_token;
}

/* True Positive: srand(time(NULL)) seeding pattern */
void test_tp_srand_time(void) {
    srand(time(NULL)); // expect: CGULL-028
}

/* True Positive: constant seed srand(1) */
void test_tp_srand_constant(void) {
    srand(1); // expect: CGULL-028
}

/* True Positive: random() used for session identifier */
void test_tp_random_session(void) {
    uint32_t session_id = random(); // expect: CGULL-028
}

/* True Positive: rand() inside security context function (nonce) */
void generate_nonce(char *out) {
    int val = rand(); // expect: CGULL-028
    (void)val;
}

/* True Positive: function context for IV generation */
void init_iv(unsigned char *iv) {
    int byte = rand(); // expect: CGULL-028
    (void)byte;
}

/* False Positive Avoidance: non-security usage (game/simulation) */
void shuffle_cards(int *deck, int count) {
    if (count <= 0) return;
    int idx = rand() % count;
    (void)idx;
}

/* False Positive Avoidance: driver variable name (short segment iv not matched substring) */
void process_driver_queue(int driver_id) {
    int val = rand() % 10;
    (void)val;
}

/* False Positive Avoidance: text inside string literal */
void log_warning_message(void) {
    char *msg = "Please do not call rand() for security tokens";
    (void)msg;
}

/* Safe Remediation: arc4random / getrandom */
void test_fp_secure_random(uint32_t *token) {
    if (token) {
        *token = arc4random();
    }
}
