/* CGULL-007 Positive Test Suite */

/* True Positive: Index equals array size (off-by-one) */
void test_tp_exact_size_index(void) {
    int table[10];
    table[10] = 42; // expect: CGULL-007
}

/* True Positive: Index exceeds array size */
void test_tp_exceeds_size_index(void) {
    char buf[16];
    buf[20] = 'X'; // expect: CGULL-007
}

/* Formatting Variation: Space and multi-line array access */
void test_formatting_spaces_in_index(void) {
    float values[5];
    values[  8  ] = 3.14f; // expect: CGULL-007
}

/* Macro & Type Variation: Typedef array out of bounds */
typedef unsigned int uint32_t;
void test_macro_type_array(void) {
    uint32_t uint_arr[4];
    uint_arr[4] = 100U; // expect: CGULL-007
}
