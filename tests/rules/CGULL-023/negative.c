/* CGULL-023 Negative Test Suite */

/* True Negative: Scalar variable initialized at declaration */
int test_tn_initialized_at_decl(int flag) {
    int status = 0;
    if (flag) {
        status = 1;
    }
    return status;
}

/* True Negative: Assigned on all branches before read */
int test_tn_assigned_all_branches(int flag) {
    int status;
    if (flag) {
        status = 1;
    } else {
        status = 0;
    }
    return status;
}

/* False-Positive Regression: Volatile variable (hardware register / MMIO read) */
int test_fp_volatile_var(void) {
    volatile int hw_status;
    return hw_status;
}

/* False-Positive Regression (#555): static buffer written by sprintf before read */
const char *test_fp_static_sprintf(void) {
    static char version[15];
    sprintf(version, "%i.%i.%i", 1, 7, 18);
    return version;
}

/* False-Positive Regression (#555): buffer filled element-wise then read */
int test_fp_buffer_fill_then_read(const unsigned char *in) {
    unsigned char number_c_string[64];
    int i = 0;
    for (; i < 63; i++) {
        number_c_string[i] = in[i];
    }
    number_c_string[i] = '\0';
    return number_c_string[0];
}

/* False-Positive Regression (#555): struct fields assigned before whole-object use */
typedef struct { int line; const char *json; } error_info;
error_info g_error;
void test_fp_struct_fields_assigned(int line, const char *json) {
    error_info local_error;
    local_error.line = line;
    local_error.json = json;
    g_error = local_error;
}

/* False-Positive Regression (#555): aggregate memset before field use */
typedef struct { char *buffer; int length; } printbuffer;
void test_fp_memset_before_use(void) {
    printbuffer buffer[1];
    memset(buffer, 0, sizeof(buffer));
    buffer[0].length = 1;
    (void)buffer[0].buffer;
}

/* False-Positive Regression (#555): declaration without use is not a defect */
void test_fp_decl_without_use(void) {
    int unused;
}
