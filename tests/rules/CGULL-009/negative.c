/* CGULL-009 Negative Test Suite */

typedef unsigned int uint32_t;

void test_tn_preserve_qualifier(volatile uint32_t *hw_reg) {
    volatile uint32_t *alias = hw_reg;
    use(alias);
}

void test_tn_nonvolatile_cast(uint32_t *value) {
    void *alias = (void *)value;
    use(alias);
}
