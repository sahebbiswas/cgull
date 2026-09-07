typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

void test_narrowing(int wide, uint32_t fixed) {
    short small = (short)wide; // expect: CGULL-049
    uint8_t byte = (uint8_t)fixed; // expect: CGULL-049
}
