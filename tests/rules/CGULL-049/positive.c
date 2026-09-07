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
