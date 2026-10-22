#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

void process_element(size_t idx);

void test_unsigned_reverse_loop_vulnerable(size_t len) {
    for (size_t i = len; i >= 0; i--) { // expect: CGULL-033
        process_element(i);
    }
}

void test_signed_loop_bound_mismatch_vulnerable(size_t len) {
    for (int i = len; i >= 0; i--) { // expect: CGULL-033
        process_element((size_t)i);
    }
}

void test_signed_unsigned_comparison_vulnerable(int signed_val, size_t unsigned_val) {
    if (signed_val < unsigned_val) { // expect: CGULL-033
        printf("Mismatch\n");
    }
}

void test_sizeof_comparison_vulnerable(int idx) {
    char buf[100];
    if (idx < sizeof(buf)) { // expect: CGULL-033
        buf[idx] = 'a';
    }
}

void test_negative_literal_comparison_vulnerable(size_t len) {
    if (len < -1) { // expect: CGULL-033
        printf("Negative comparison\n");
    }
}

void test_reverse_loop_safe(size_t len) {
    for (size_t i = len; i > 0; i--) {
        process_element(i - 1);
    }
}

void test_signed_comparison_safe(int a, int b) {
    if (a < b) {
        printf("Both signed\n");
    }
}

void test_unsigned_comparison_safe(size_t a, size_t b) {
    if (a < b) {
        printf("Both unsigned\n");
    }
}

#include <string.h>

/* Pointer overlap test (cJSON_SetValuestring shape, #588): pointer provenance, not integer signedness */
int test_pointer_overlap_safe(char *dst, const char *src) {
    size_t src_len = strlen(src);
    size_t dst_len = strlen(dst);
    if (!(src + src_len < dst || dst + dst_len < src)) {
        return 0;
    }
    return 1;
}

/* Integer comparison next to pointer code must still report */
int test_int_vs_size_next_to_pointer_code_vulnerable(char *p, char *end, int i, size_t len) {
    if (p + len < end) {
        return 1;
    }
    if (i < len) { // expect: CGULL-033
        return 2;
    }
    return 0;
}
