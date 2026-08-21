/* CGULL-007 Negative Test Suite */

/* True Negative: Index within array bounds */
void test_tn_valid_index(void) {
    int table[10];
    table[9] = 42;
}

/* True Negative: Index zero on non-empty array */
void test_tn_first_element(void) {
    char buf[16];
    buf[0] = 'A';
}

/* False-Positive Regression: Array declaration line not flagged as indexing */
void test_fp_declaration_line(void) {
    int buffer[100];
    (void)buffer;
}

/* False-Positive Regression: Array declaration with initializer */
void test_fp_declaration_with_initializer(void) {
    char dataBuffer[100] = "";
    (void)dataBuffer;
}

/* False-Positive Regression: memset/memcpy style loop using size_t */
void test_memset_size_t_loop(uint8_t *ptr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        ptr[i] = 0;
    }
}

/* False-Positive Regression: memset/memcpy style loop using uint8_t index */
void test_memset_uint8_t_loop(uint8_t *ptr, uint8_t size) {
    for (uint8_t i = 0; i < size; i++) {
        ptr[i] = 0;
    }
}

/* False-Positive Regression: memset/memcpy style loop using unsigned int index */
void test_memset_unsigned_int_loop(uint8_t *ptr, unsigned int size) {
    for (unsigned int i = 0; i < size; i++) {
        ptr[i] = 0;
    }
}

/* True Negative: Variable index with bounds check */
void test_tn_variable_index_checked(int idx) {
    int table[10];
    if (idx >= 0 && idx < 10) {
        table[idx] = 42;
    }
}

/* False-Positive Regression: Array declaration with initializer after earlier declaration */
void other_function_decl(void) {
    char dataBuffer[100];
    dataBuffer[0] = 'x';
}

void test_fp_declaration_with_initializer_and_prior_decl(void) {
    char dataBuffer[100] = "";
    (void)dataBuffer;
}
