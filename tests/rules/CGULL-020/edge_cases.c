/* CGULL-020 Edge Cases Test Suite */

int test_edge_pointer_parameter(int used, void *context) { // expect: CGULL-020
    return used;
}

int test_edge_named_unused(int used, int unused_value) {
    return used;
}
