/* CGULL-008 Edge Cases Test Suite */

struct Session {
    char session_key[32];
};

void test_edge_member_wipe(struct Session *session) {
    memset(session->session_key, 0, sizeof(session->session_key)); // expect: CGULL-008
    return;
}

void test_edge_nonzero_fill(void) {
    char secret_key[32];
    memset(secret_key, 1, sizeof(secret_key));
}
