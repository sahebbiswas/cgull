typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

void test_safe_casts(uint8_t small, uint32_t same) {
    uint32_t wide = (uint32_t)small;
    unsigned int unchanged = (unsigned int)same;
}

void test_proven_safe_narrowing(uint32_t guarded) {
    uint32_t constant = 42;
    uint8_t from_constant = constant;
    if (guarded <= UINT8_MAX) {
        uint8_t from_guard = guarded;
    }
}

void test_non_integer(double value) {
    float narrowed = (float)value;
}

void test_safe_signedness(int signed_value, unsigned int unsigned_value) {
    if (signed_value < 0) return;
    unsigned int nonnegative = signed_value;
    if (unsigned_value > INT_MAX) return;
    int representable = unsigned_value;
}
