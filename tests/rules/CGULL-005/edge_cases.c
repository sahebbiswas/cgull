/* CGULL-005 Edge Cases Test Suite */

typedef unsigned char crypto_key_t;

int test_edge_sensitive_type(const crypto_key_t *left, const crypto_key_t *right) {
    return memcmp(left, right, 32); // expect: CGULL-005
}

int test_edge_metadata_compare(int key_count, int max_keys) {
    return memcmp(&key_count, &max_keys, sizeof(int));
}
