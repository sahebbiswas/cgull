"""
Unit tests for BannedFunctionsRule (CGULL-001) struct member destination size resolution across V1-V7 variants,
multidimensional arrays, exact-fit strcpy, flexible array members, and non-byte arrays.
"""

from cgull.engine import CGullScanner
from cgull.models import Severity
from cgull.rules.banned_functions import BannedFunctionsRule


STRUCT_TEST_CODE = """
#include <string.h>

struct Inner {
    char inner_buf[50];
};

struct A {
    char array_a[100];
    struct Inner in;
    struct Inner *in_ptr;
    char matrix[4][8];
    char flex[];
};

struct NonByte {
    int int_arr[10];
};

typedef struct A A_t;

/* V1: direct pointer, single level */
void test_v1_overflow(struct A *a) {
    strcpy(a->array_a, "This is a long string literal that contains well over one hundred characters in total length, specifically designed to exceed the one hundred byte capacity of the array_a field in struct A!");
}

void test_v1_bounded(struct A *a) {
    strcpy(a->array_a, "short");
}

/* V2: by-value struct, single level */
void test_v2_overflow(struct A a_val) {
    strcpy(a_val.array_a, "This is a long string literal that contains well over one hundred characters in total length, specifically designed to exceed the one hundred byte capacity of the array_a field in struct A!");
}

void test_v2_bounded(struct A a_val) {
    strcpy(a_val.array_a, "short");
}

/* V3: pointer -> nested-by-value member */
void test_v3_overflow(struct A *a) {
    strcpy(a->in.inner_buf, "This literal is definitely longer than fifty bytes in size!");
}

void test_v3_bounded(struct A *a) {
    strcpy(a->in.inner_buf, "short");
}

/* V4: pointer -> nested-pointer member */
void test_v4_overflow(struct A *a) {
    strcpy(a->in_ptr->inner_buf, "This literal is definitely longer than fifty bytes in size!");
}

void test_v4_bounded(struct A *a) {
    strcpy(a->in_ptr->inner_buf, "short");
}

/* V5: array-of-structs, indexed instance */
void test_v5_overflow(struct A arr[10]) {
    strcpy(arr[0].array_a, "This is a long string literal that contains well over one hundred characters in total length, specifically designed to exceed the one hundred byte capacity of the array_a field in struct A!");
}

void test_v5_bounded(struct A arr[10]) {
    strcpy(arr[0].array_a, "short");
}

/* V6: array-of-struct-pointers */
void test_v6_overflow(struct A *parr[10]) {
    strcpy(parr[0]->array_a, "This is a long string literal that contains well over one hundred characters in total length, specifically designed to exceed the one hundred byte capacity of the array_a field in struct A!");
}

void test_v6_bounded(struct A *parr[10]) {
    strcpy(parr[0]->array_a, "short");
}

/* V7: typedef indirection */
void test_v7_overflow(A_t *b) {
    strcpy(b->array_a, "This is a long string literal that contains well over one hundred characters in total length, specifically designed to exceed the one hundred byte capacity of the array_a field in struct A!");
}

void test_v7_bounded(A_t *b) {
    strcpy(b->array_a, "short");
}

/* Offset indexing */
void test_offset_overflow(struct A *a) {
    strcpy(&a->array_a[90], "This is 20 chars long!");
}

void test_offset_bounded(struct A *a) {
    strcpy(&a->array_a[90], "hi");
}

/* Non-literal source variable */
void test_non_literal_src(struct A *a, const char *src) {
    strcpy(a->array_a, src);
}

/* Exact-fit strcpy: 7 chars + '\\0' = 8 bytes into 8-byte row capacity */
void test_exact_fit(struct A *a) {
    strcpy(a->matrix[2], "1234567");
}

/* Multidimensional overflow: 8 chars + '\\0' = 9 bytes into 8-byte row capacity */
void test_matrix_row_overflow(struct A *a) {
    strcpy(a->matrix[2], "12345678");
}

/* Multidimensional address offset: &a->matrix[2][3] leaves 5 bytes (8 - 3). "1234" (4 chars + '\\0' = 5 bytes) is exact fit */
void test_matrix_addr_exact(struct A *a) {
    strcpy(&a->matrix[2][3], "1234");
}

void test_matrix_addr_overflow(struct A *a) {
    strcpy(&a->matrix[2][3], "12345");
}

/* Flexible array member: capacity unknown -> generic banned function finding */
void test_flex_array(struct A *a, const char *src) {
    strcpy(a->flex, "short");
}

/* Non-byte array: capacity unknown -> generic banned function finding */
void test_non_byte_array(struct NonByte *nb) {
    strcpy((char *)nb->int_arr, "short");
}
"""


def test_strcpy_struct_member_dest_size_v1_to_v7():
    scanner = CGullScanner(rules=[BannedFunctionsRule()])
    res = scanner.scan_text(STRUCT_TEST_CODE, file_path="test_struct.c")

    issues_by_line = {issue.line_number: issue for issue in res.issues}

    # Verify that overflow functions trigger Severity.HIGH provable overflow issues
    overflow_lines = [24, 33, 42, 51, 60, 69, 78, 87]
    for line_no in overflow_lines:
        assert line_no in issues_by_line, f"Expected issue at line {line_no}"
        issue = issues_by_line[line_no]
        assert issue.impact == Severity.HIGH, f"Line {line_no}: expected Severity.HIGH, got {issue.impact}"
        assert "exceeds destination buffer size" in issue.message or "Buffer Overflow" in issue.message

    # Verify that bounded functions trigger Severity.LOW fragile issues
    bounded_lines = [28, 37, 46, 55, 64, 73, 82, 91]
    for line_no in bounded_lines:
        assert line_no in issues_by_line, f"Expected issue at line {line_no}"
        issue = issues_by_line[line_no]
        assert issue.impact == Severity.LOW, f"Line {line_no}: expected Severity.LOW, got {issue.impact}"
        assert "provably shorter than destination buffer size" in issue.message
        assert "fragile to future edits" in issue.message

    # Verify non-literal source gives standard banned function warning with Severity.HIGH
    assert 96 in issues_by_line
    assert issues_by_line[96].impact == Severity.HIGH
    assert "Banned insecure function call" in issues_by_line[96].message

    # Exact-fit test (line 101): 7 chars + null = 8 bytes into 8-byte row -> Severity.LOW (bounded/fragile)
    assert 101 in issues_by_line
    assert issues_by_line[101].impact == Severity.LOW
    assert "provably shorter than destination buffer size" in issues_by_line[101].message

    # Matrix row overflow (line 106): 8 chars + null = 9 bytes into 8-byte row -> Severity.HIGH
    assert 106 in issues_by_line
    assert issues_by_line[106].impact == Severity.HIGH
    assert "exceeds destination buffer size" in issues_by_line[106].message

    # Matrix addr offset exact fit (line 111): 4 chars + null = 5 bytes into 5-byte remaining -> Severity.LOW
    assert 111 in issues_by_line
    assert issues_by_line[111].impact == Severity.LOW

    # Matrix addr offset overflow (line 115): 5 chars + null = 6 bytes into 5-byte remaining -> Severity.HIGH
    assert 115 in issues_by_line
    assert issues_by_line[115].impact == Severity.HIGH

    # Flexible array member (line 120): capacity unknown -> generic banned function finding (Severity.HIGH)
    assert 120 in issues_by_line
    assert issues_by_line[120].impact == Severity.HIGH
    assert "Banned insecure function call" in issues_by_line[120].message

    # Non-byte array (line 125): capacity unknown -> generic banned function finding (Severity.HIGH)
    assert 125 in issues_by_line
    assert issues_by_line[125].impact == Severity.HIGH
    assert "Banned insecure function call" in issues_by_line[125].message
