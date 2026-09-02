/* CGULL-015 Negative Test Suite */

unsigned int test_tn_unsigned_shift(unsigned int value) {
    return value << 2U;
}

unsigned int test_tn_unsigned_mask(void) {
    unsigned int mask = 0xFFFFFFFFU;
    mask >>= 2U;
    return mask;
}
