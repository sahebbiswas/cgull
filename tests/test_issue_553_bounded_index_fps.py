"""CGULL-007: sizeof-bounded loops, can_access macros, and ensure()-sized buffers (#553)."""

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import ArrayIndexOutOfBoundsRule


def _scan(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return [issue for issue in ArrayIndexOutOfBoundsRule().scan_ast("issue_553.c", ctx) if issue.rule_id == "CGULL-007"]


def test_sizeof_bounded_loop_and_post_loop_nul_write():
    code = """
    void parse_number(void) {
        unsigned char number_c_string[64];
        size_t i = 0;
        for (i = 0; i < (sizeof(number_c_string) - 1); i++) {
            number_c_string[i] = '0';
        }
        number_c_string[i] = '\\0';
    }
    """
    assert _scan(code) == []


def test_sizeof_bounded_loop_with_can_access_macro():
    code = """
    typedef struct {
        const unsigned char *content;
        size_t length;
        size_t offset;
    } parse_buffer;
    #define can_access_at_index(buffer, index) \\
        ((buffer != 0) && (((buffer)->offset + (index)) < (buffer)->length))
    #define buffer_at_offset(buffer) ((buffer)->content + (buffer)->offset)

    static void parse_number(parse_buffer * const input_buffer) {
        unsigned char number_c_string[64];
        size_t i = 0;
        for (i = 0; (i < (sizeof(number_c_string) - 1)) && can_access_at_index(input_buffer, i); i++) {
            number_c_string[i] = buffer_at_offset(input_buffer)[i];
        }
        number_c_string[i] = '\\0';
    }
    """
    assert _scan(code) == []


def test_can_access_macro_alone_guards_cursor_access():
    code = """
    typedef struct {
        const unsigned char *content;
        size_t length;
        size_t offset;
    } parse_buffer;
    #define can_access_at_index(buffer, index) \\
        ((buffer != 0) && (((buffer)->offset + (index)) < (buffer)->length))
    #define buffer_at_offset(buffer) ((buffer)->content + (buffer)->offset)

    void f(parse_buffer *buffer, size_t i) {
        if (can_access_at_index(buffer, i)) {
            unsigned char c = buffer_at_offset(buffer)[i];
            (void)c;
        }
    }
    """
    assert _scan(code) == []


def test_length_validated_against_sizeof_then_loop():
    code = """
    void print_number(int length) {
        unsigned char number_buffer[26];
        size_t i;
        if ((length < 0) || (length > (int)(sizeof(number_buffer) - 1))) {
            return;
        }
        for (i = 0; i < ((size_t)length); i++) {
            number_buffer[i] = number_buffer[i];
        }
    }
    """
    assert _scan(code) == []


def test_ensure_then_write_closing_quote_and_nul():
    code = r"""
    typedef struct {
        unsigned char *buffer;
        size_t length;
        size_t offset;
    } printbuffer;
    static unsigned char *ensure(printbuffer * const p, size_t needed);

    static void print_string_ptr(printbuffer * const output_buffer, size_t output_length) {
        unsigned char *output = ensure(output_buffer, output_length + sizeof("\"\""));
        if (output == 0) {
            return;
        }
        output[0] = '\"';
        output[output_length + 1] = '\"';
        output[output_length + 2] = '\0';
    }
    """
    assert _scan(code) == []


def test_ensure_insufficient_size_still_reported():
    code = """
    unsigned char *ensure(void *p, size_t needed);
    void f(void *pb, size_t output_length) {
        unsigned char *output = ensure(pb, output_length + 1);
        if (output == 0) return;
        output[output_length + 1] = 0;
    }
    """
    issues = _scan(code)
    assert issues
    assert any("output_length" in issue.message for issue in issues)


def test_parse_hex4_needs_context_still_reported():
    code = """
    static unsigned parse_hex4(const unsigned char * const input) {
        size_t i = 0;
        unsigned int h = 0;
        for (i = 0; i < 4; i++) {
            h += (unsigned int) input[i];
        }
        return h;
    }
    """
    issues = _scan(code)
    assert len(issues) == 1
    assert "input" in issues[0].message


def test_genuine_unchecked_index_still_reported():
    code = """
    void bad(int idx) {
        int table[10];
        table[idx] = 42;
    }
    """
    issues = _scan(code)
    assert len(issues) == 1
    assert "idx" in issues[0].message


def test_insufficient_constant_bound_still_reported():
    code = """
    void f(unsigned idx) {
        int data[16];
        if (idx < 32) {
            data[idx] = 0;
        }
    }
    """
    assert _scan(code)


def test_ensure_access_before_ensure_still_reported():
    """Accesses before ensure() must not use a later capacity proof."""
    code = """
    unsigned char *ensure(void *p, size_t needed);
    void f(void *pb, size_t n) {
        unsigned char *output;
        output[n + 1] = 0;
        output = ensure(pb, n + 3);
        if (output == 0) return;
        output[n + 1] = 1;
    }
    """
    issues = _scan(code)
    assert any("output" in issue.message and "n" in issue.message for issue in issues)


def test_ensure_access_before_null_check_still_reported():
    """ensure() alone does not suppress; null check must dominate the access."""
    code = """
    unsigned char *ensure(void *p, size_t needed);
    void f(void *pb, size_t n) {
        unsigned char *output = ensure(pb, n + 3);
        output[n + 1] = 0;
        if (output == 0) return;
    }
    """
    issues = _scan(code)
    assert any("output" in issue.message and "n" in issue.message for issue in issues)


def test_ensure_other_branch_still_reported():
    """ensure() on one branch must not suppress accesses on the other."""
    code = """
    unsigned char *ensure(void *p, size_t needed);
    void f(void *pb, size_t n, int flag) {
        unsigned char *output;
        if (flag) {
            output = ensure(pb, n + 3);
            if (output == 0) return;
            output[n + 1] = 1;
        } else {
            output[n + 1] = 2;
        }
    }
    """
    issues = _scan(code)
    assert any("output" in issue.message and "n" in issue.message for issue in issues)


def test_ensure_after_reassignment_still_reported():
    """Reassigning the pointer kills the ensure capacity proof."""
    code = """
    unsigned char *ensure(void *p, size_t needed);
    void f(void *pb, size_t n, unsigned char *other) {
        unsigned char *output = ensure(pb, n + 3);
        if (output == 0) return;
        output = other;
        output[n + 1] = 0;
    }
    """
    issues = _scan(code)
    assert any("output" in issue.message and "n" in issue.message for issue in issues)


def test_post_loop_body_mutates_counter_still_reported():
    """Loop body writes to the counter → post-loop arr[i] is not proven."""
    code = """
    void f(void) {
        unsigned char buf[8];
        size_t i;
        for (i = 0; i < 4; i++) {
            i = 100;
            buf[i] = 0;
        }
        buf[i] = 0;
    }
    """
    issues = _scan(code)
    assert issues


def test_post_loop_compound_write_before_access_still_reported():
    """Ordered invalidation: { i = 100; arr[i] = 0; } after a sizeof loop."""
    code = """
    void f(void) {
        unsigned char buf[8];
        size_t i;
        for (i = 0; i < 4; i++) {
            buf[i] = 1;
        }
        {
            i = 100;
            buf[i] = 0;
        }
    }
    """
    issues = _scan(code)
    assert any("buf" in issue.message for issue in issues)


def test_post_loop_body_break_still_reported():
    """break in the body rejects the post-loop induction proof."""
    code = """
    void f(int stop) {
        unsigned char buf[8];
        size_t i;
        for (i = 0; i < 4; i++) {
            if (stop) break;
            buf[i] = 1;
        }
        buf[i] = 0;
    }
    """
    issues = _scan(code)
    assert issues
