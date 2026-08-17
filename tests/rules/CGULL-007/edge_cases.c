/* CGULL-007 Edge Cases Test Suite */

/* Struct array member out of bounds */
struct Buffer {
    char data[8];
};

void test_edge_struct_array(struct Buffer *b) {
    char stack_buf[8];
    stack_buf[12] = 'E'; // expect: CGULL-007
}
