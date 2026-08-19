/* CGULL-028 Insecure PRNG Test Suite */
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/* True Positive: rand() used for security token */
void test_tp_rand_token(void) {
    int token = rand(); // expect: CGULL-028
}

/* True Positive: srand(time(NULL)) seeding pattern */
void test_tp_srand_time(void) {
    srand(time(NULL)); // expect: CGULL-028
}

/* True Positive: random() used for session identifier */
void test_tp_random_session(void) {
    uint32_t session_id = random(); // expect: CGULL-028
}

/* True Positive: rand() inside security context function */
void generate_crypto_nonce(char *out) {
    int val = rand(); // expect: CGULL-028
    (void)val;
}

/* False Positive Avoidance: non-security usage (game/simulation) */
void shuffle_cards(int *deck, int count) {
    if (count <= 0) return;
    int idx = rand() % count;
    (void)idx;
}

/* Safe Remediation: arc4random / getrandom */
void test_fp_secure_random(uint32_t *token) {
    if (token) {
        *token = arc4random();
    }
}
