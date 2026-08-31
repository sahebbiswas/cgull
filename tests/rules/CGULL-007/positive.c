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

/* True Positive: Variable index without preceding bounds validation */
void test_tp_variable_index_unvalidated(int idx) {
    int table[10];
    table[idx] = 42; // expect: CGULL-007
}

/* True Positive: recv return value used as index without bounds check */
void test_tp_recv_result_unvalidated(int recvResult) {
    char dataBuffer[100] = "";
    char *data = dataBuffer;
    data[recvResult] = '\0'; // expect: CGULL-007
}

/* True Positive: NIST Juliet CWE-121 stack buffer overflow via pointer aliasing */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_loop_01_bad(void) {
    int * data;
    int dataBadBuffer[50];
    int dataGoodBuffer[100];
    data = dataBadBuffer;
    {
        int source[100] = {0};
        unsigned long i;
        for (i = 0; i < 100; i++) {
            data[i] = source[i]; // expect: CGULL-007
        }
    }
}

/* True Positive: Offset pointer aliasing reduces effective buffer capacity */
void test_tp_pointer_alias_offset_oob(int idx) {
    char buf[10];
    char *ptr = &buf[3];
    ptr[7] = 'A'; // expect: CGULL-007
}

void test_tp_pointer_alias_arith_oob(int idx) {
    char buf[10];
    char *ptr = buf + 5;
    ptr[5] = 'B'; // expect: CGULL-007
}

/* Scope isolation: function 1 has buf[100], function 2 has buf[10] */
void helper_large_buf(void) {
    char buf[100];
    buf[0] = 'X';
}

void test_scope_isolated_small_buf(void) {
    char buf[10];
    char *ptr = buf;
    ptr[15] = 'Y'; // expect: CGULL-007
}

/* Heap capacities are tracked in element units, including through aliases. */
void test_tp_malloc_capacity(void) {
    char *data = (char *)malloc(10);
    data[10] = 'X'; // expect: CGULL-007
}

void test_tp_calloc_capacity(void) {
    char *data = (char *)calloc(2, 5);
    data[10] = 'X'; // expect: CGULL-007
}

void test_tp_realloc_capacity(char *old_data) {
    char *data = (char *)realloc(old_data, 10);
    data[10] = 'X'; // expect: CGULL-007
}

void test_tp_malloc_alias_capacity(void) {
    char *data = (char *)malloc(10);
    char *alias = data;
    alias[10] = 'X'; // expect: CGULL-007
}

void test_tp_malloc_incorrect_guard(int idx) {
    char *data = (char *)malloc(10);
    if (idx >= 0 && idx < 11) {
        data[idx] = 'X'; // expect: CGULL-007
    }
}
