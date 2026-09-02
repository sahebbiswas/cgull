/* CGULL-014 Edge Cases Test Suite */

typedef unsigned char uint8_t;

void test_edge_spacing(void) {
    uint8_t packet[ 512 ]; // expect: CGULL-014
    use(packet);
}

void test_edge_expression_bound(void) {
    char buffer[32 + 1];
    use(buffer);
}
