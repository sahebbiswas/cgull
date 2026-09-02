/* CGULL-044 Edge Cases Test Suite */

struct Inner {
    char buffer[50];
};

struct Outer {
    struct Inner inner;
};

void test_edge_nested_member(struct Outer *outer) {
    memset(outer->inner.buffer, 0, 60); // expect: CGULL-044
}

void test_edge_unchecked_dynamic_size(char *source, size_t size) {
    char buffer[100];
    memcpy(buffer, source, size); // expect: CGULL-044
}

void test_edge_multiline_call(struct Outer *outer, const char *source) {
    memcpy( // expect: CGULL-044
        outer->inner.buffer,
        source,
        75
    );
}
