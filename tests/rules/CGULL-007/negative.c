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

/* Explicit capacity contract: memset/memcpy style loop using size_t */
void test_memset_size_t_loop(size_t size, uint8_t ptr[static size]) {
    for (size_t i = 0; i < size; i++) {
        ptr[i] = 0;
    }
}

/* Explicit capacity contract: memset/memcpy style loop using uint8_t index */
void test_memset_uint8_t_loop(uint8_t size, uint8_t ptr[static size]) {
    for (uint8_t i = 0; i < size; i++) {
        ptr[i] = 0;
    }
}

/* Explicit capacity contract: memset/memcpy style loop using unsigned int index */
void test_memset_unsigned_int_loop(unsigned int size, uint8_t ptr[static size]) {
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

/* Allocation capacity remains unknown when its size expression is unknown. */
void test_tn_unknown_malloc_capacity(size_t n) {
    char *data = (char *)malloc(n);
    data[10] = 'X';
}

void test_tn_malloc_checked_index(int idx) {
    char *data = (char *)malloc(10);
    if (idx >= 0 && idx < 10) {
        data[idx] = 'X';
    }
}

/* Short-circuit guards apply before the right operand and in the body. */
void test_tn_short_circuit_while(unsigned idx) {
    int data[16] = {0};
    while (idx < 16 && data[idx]) {
        data[idx] = 0;
        ++idx;
    }
}

void test_tn_short_circuit_signed(int idx) {
    int data[16] = {0};
    if (idx >= 0 && idx < 16 && data[idx]) {
        data[idx] = 0;
    }
}
/* False-Positive Regression (#553): sizeof-bounded loop + post-loop NUL write */
void test_fp_sizeof_bounded_loop(void) {
    unsigned char number_c_string[64];
    size_t i = 0;
    for (i = 0; i < (sizeof(number_c_string) - 1); i++) {
        number_c_string[i] = '0';
    }
    number_c_string[i] = '\0';
}

/* False-Positive Regression (#553): can_access_at_index-style cursor guard */
typedef struct {
    const unsigned char *content;
    size_t length;
    size_t offset;
} cgull007_parse_buffer;

#define cgull007_can_access_at_index(buffer, index) \
    ((buffer != 0) && (((buffer)->offset + (index)) < (buffer)->length))
#define cgull007_buffer_at_offset(buffer) ((buffer)->content + (buffer)->offset)

void test_fp_can_access_cursor(cgull007_parse_buffer *buffer, size_t i) {
    if (cgull007_can_access_at_index(buffer, i)) {
        unsigned char c = cgull007_buffer_at_offset(buffer)[i];
        (void)c;
    }
}

/* False-Positive Regression (#553): ensure()-sized buffer writes */
unsigned char *ensure(void *p, size_t needed);
void test_fp_ensure_then_write(void *pb, size_t output_length) {
    unsigned char *output = ensure(pb, output_length + sizeof("\"\""));
    if (output == 0) {
        return;
    }
    output[0] = '\"';
    output[output_length + 1] = '\"';
    output[output_length + 2] = '\0';
}

/* False-Positive Regression (#553): length validated against sizeof then looped */
void test_fp_length_validated_sizeof_loop(int length) {
    unsigned char number_buffer[26];
    size_t i;
    if ((length < 0) || (length > (int)(sizeof(number_buffer) - 1))) {
        return;
    }
    for (i = 0; i < ((size_t)length); i++) {
        number_buffer[i] = 0;
    }
}
