/* CGULL-009 Positive Test Suite */

typedef unsigned int uint32_t;

void test_tp_strip_parameter(volatile uint32_t *hw_reg) {
    uint32_t *plain = (uint32_t *)hw_reg; // expect: CGULL-009
    use(plain);
}

void test_tp_strip_local(void) {
    volatile uint32_t shared_state = 0;
    uint32_t *plain = (uint32_t *)&shared_state; // expect: CGULL-009
    use(plain);
}
