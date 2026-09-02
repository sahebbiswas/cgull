/* CGULL-010 Edge Cases Test Suite */

void test_edge_multiline_declaration(int length) {
    unsigned char
        packet[length]; // expect: CGULL-010
    use(packet);
}

void test_edge_heap_allocation(int length) {
    char *buffer = malloc(length);
    use(buffer);
    free(buffer);
}
