typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

void log_value(uint32_t value) { (void)value; }

void test_narrowing(int wide, uint32_t fixed) {
    short small = (short)wide; // expect: CGULL-049
    uint8_t byte = (uint8_t)fixed; // expect: CGULL-049
}

void test_non_dominating_guard(uint32_t value) {
    if (value <= UINT8_MAX)
        log_value(value);
    uint8_t byte = value; // expect: CGULL-049
}

void test_signedness(int signed_value, unsigned int unsigned_value) {
    unsigned int negative_risk = signed_value; // expect: CGULL-049
    int large_risk = unsigned_value; // expect: CGULL-049
}

void test_sign_extension(signed char byte, short word, char target_dependent) {
    int byte_value = byte; // expect: CGULL-049
    long word_value = word; // expect: CGULL-049
    int uncertain_value = target_dependent; // expect: CGULL-049
}
