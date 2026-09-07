typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

void test_safe_casts(uint8_t small, uint32_t same) {
    uint32_t wide = (uint32_t)small;
    unsigned int unchanged = (unsigned int)same;
}

void test_non_integer(double value) {
    float narrowed = (float)value;
}
