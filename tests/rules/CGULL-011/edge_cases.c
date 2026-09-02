/* CGULL-011 Edge Cases Test Suite */

void do_step(int value) {
    (void)value;
}

void test_edge_neutral_function_name(void) {
    void *opaque = (void *)do_step; // expect: CGULL-011
    use(opaque);
}

void test_edge_object_pointer_cast(void *object) {
    unsigned long address = (unsigned long)object;
    use(address);
}
