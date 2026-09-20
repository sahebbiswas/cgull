/* CGULL-006 Positive Test Suite */
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

/* True Positive: Unchecked multiplication in malloc argument */
void test_tp_malloc_mult(int count) {
    int *buf = malloc(count * 4); // expect: CGULL-006
    (void)buf;
}

/* True Positive: Unchecked addition in malloc argument */
void test_tp_malloc_add(size_t base_len, size_t extra) {
    char *buf = malloc(base_len + extra); // expect: CGULL-006
    (void)buf;
}

/* Formatting Variation: Multi-line / space variations in malloc arithmetic */
void test_formatting_multiline_alloc(size_t num) {
    void *ptr = malloc(num * 64); // expect: CGULL-006
    (void)ptr;
}

/* Macro Variation: Unchecked multiplication in macro-expanded size */
#define ALLOC_ARRAY(n, sz) malloc(n * sz) // expect: CGULL-006
void test_macro_mult(size_t n) {
    char *arr = ALLOC_ARRAY(n, 128);
    (void)arr;
}

/* True Positive: General CWE-190 addition near INT_MAX */
void test_tp_int_max_add(void) {
    int data = 2147483647; // INT_MAX
    int result = data + 1; // expect: CGULL-006
    (void)result;
}

/* True Positive: console input converted to integer then incremented */
void test_tp_fgets_taint(void) {
    char input[32];
    int data = 0;
    if (fgets(input, sizeof(input), stdin)) {
        data = atoi(input);
    }
    int result = data + 1; // expect: CGULL-006
    (void)result;
}

/* True Positive: argv-derived integer arithmetic */
void test_tp_argv_taint(int argc, char **argv) {
    if (argc < 2) return;
    int data = atoi(argv[1]);
    int result = data * 2; // expect: CGULL-006
    (void)result;
}

/* True Positive: read buffer converted to integer then incremented */
void test_tp_read_taint(int fd) {
    char input[32];
    (void)read(fd, input, sizeof(input));
    int data = atoi(input);
    data++; // expect: CGULL-006
}

/* True Positive: ensure()-style INT_MAX gate then size accumulation feeding realloc (#560) */
typedef struct {
    unsigned char *buffer;
    size_t length;
    size_t offset;
} printbuffer;
void *test_tp_ensure_style_accum(printbuffer *p, size_t needed) {
    unsigned char *newbuffer;
    size_t newsize;
    if (needed > INT_MAX) {
        return 0;
    }
    needed += p->offset + 1; // expect: CGULL-006
    if (needed <= p->length) {
        return p->buffer + p->offset;
    }
    newsize = needed * 2; // expect: CGULL-006
    newbuffer = realloc(p->buffer, newsize);
    return newbuffer;
}

/* True Positive: partial INT_MAX gate does not prove add-in-alloc-arg safety (#560) */
void *test_tp_intmax_then_realloc_add(void *buf, size_t needed, size_t offset) {
    if (needed > INT_MAX) {
        return 0;
    }
    return realloc(buf, needed + offset); // expect: CGULL-006
}
