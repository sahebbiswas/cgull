/* CGULL-007 Edge Cases Test Suite */

/* Struct array member out of bounds */
struct Buffer {
    char data[8];
};

void test_edge_struct_array(struct Buffer *b) {
    char stack_buf[8];
    stack_buf[12] = 'E'; // expect: CGULL-007
}

/* Negative constant subscripts are statically out of bounds. */
int test_negative_constant_indices(void) {
    int values[4] = {0};
    int total = values[-1]; // expect: CGULL-007
    total += values[-(1)]; // expect: CGULL-007
    total += values[0 - 1]; // expect: CGULL-007
    total += values[0];
    total += values[4 - 1];
    return total;
}
