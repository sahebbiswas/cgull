/* CGULL-009 Edge Cases Test Suite */

typedef unsigned int uint32_t;

void test_edge_neutral_name(volatile uint32_t *value) {
    uint32_t *plain = (uint32_t *)value; // expect: CGULL-009
    use(plain);
}

void test_edge_explicit_volatile_cast(volatile uint32_t *value) {
    volatile uint32_t *alias = (volatile uint32_t *)value;
    use(alias);
}
