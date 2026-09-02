/* CGULL-011 Positive Test Suite */

void handle_event(int event) {
    (void)event;
}

void test_tp_function_to_object_pointer(void) {
    void *callback = (void *)handle_event; // expect: CGULL-011
    use(callback);
}

void test_tp_function_to_integer(void) {
    unsigned long address = (unsigned long)handle_event; // expect: CGULL-011
    use(address);
}
