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
