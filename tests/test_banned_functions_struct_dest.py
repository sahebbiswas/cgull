"""
Unit tests for BannedFunctionsRule (CGULL-001) struct member destination size resolution across V1-V7 variants.
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
"""


def test_strcpy_struct_member_dest_size_v1_to_v7():
    scanner = CGullScanner(rules=[BannedFunctionsRule()])
    res = scanner.scan_text(STRUCT_TEST_CODE, file_path="test_struct.c")

    issues_by_line = {issue.line_number: issue for issue in res.issues}

    # Verify that overflow functions trigger Severity.HIGH provable overflow issues
    overflow_lines = [18, 27, 36, 45, 54, 63, 72, 81]
    for line_no in overflow_lines:
        assert line_no in issues_by_line, f"Expected issue at line {line_no}"
        issue = issues_by_line[line_no]
        assert issue.impact == Severity.HIGH, f"Line {line_no}: expected Severity.HIGH, got {issue.impact}"
        assert "exceeds destination buffer size" in issue.message or "Buffer Overflow" in issue.message

    # Verify that bounded functions trigger Severity.LOW fragile issues
    bounded_lines = [22, 31, 40, 49, 58, 67, 76, 85]
    for line_no in bounded_lines:
        assert line_no in issues_by_line, f"Expected issue at line {line_no}"
        issue = issues_by_line[line_no]
        assert issue.impact == Severity.LOW, f"Line {line_no}: expected Severity.LOW, got {issue.impact}"
        assert "provably shorter than destination buffer size" in issue.message
        assert "fragile to future edits" in issue.message

    # Verify non-literal source gives standard banned function warning with Severity.HIGH
    assert 90 in issues_by_line
    assert issues_by_line[90].impact == Severity.HIGH
    assert "Banned insecure function call" in issues_by_line[90].message
