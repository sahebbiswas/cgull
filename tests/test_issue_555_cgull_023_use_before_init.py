"""Regressions for #555 (CGULL-023 use-before-init vs decl-without-init)."""

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


def _scan(code: str):
    rule = get_rule_by_id("CGULL-023")
    return [
        issue
        for issue in CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
        .scan_text(code, "CGULL-023.c")
        .issues
        if issue.rule_id == "CGULL-023"
    ]


def test_conditional_scalar_use_before_init_still_reported():
    issues = _scan(
        """
        int f(int flag) {
            int status;
            if (flag) {
                status = 1;
            }
            return status;
        }
        """
    )
    assert len(issues) == 1
    assert issues[0].line_number == 7
    assert "status" in issues[0].message
    assert "declared at line" in issues[0].message


def test_all_branches_assigned_is_silent():
    assert (
        _scan(
            """
            int f(int flag) {
                int status;
                if (flag) status = 1;
                else status = 0;
                return status;
            }
            """
        )
        == []
    )


def test_decl_without_use_is_silent():
    assert (
        _scan(
            """
            void f(void) {
                int unused;
            }
            """
        )
        == []
    )


def test_static_sprintf_buffer_is_silent():
    assert (
        _scan(
            """
            const char *f(void) {
                static char version[15];
                sprintf(version, "%i.%i.%i", 1, 7, 18);
                return version;
            }
            """
        )
        == []
    )


def test_buffer_fill_then_read_is_silent():
    assert (
        _scan(
            """
            int f(const unsigned char *in) {
                unsigned char number_c_string[64];
                int i = 0;
                for (; i < 63; i++) {
                    number_c_string[i] = in[i];
                }
                number_c_string[i] = '\\0';
                return (int)number_c_string[0];
            }
            """
        )
        == []
    )


def test_struct_fields_assigned_before_copy_is_silent():
    assert (
        _scan(
            """
            typedef struct { int line; const char *json; } error;
            error g;
            void f(int line, const char *json) {
                error local_error;
                local_error.line = line;
                local_error.json = json;
                g = local_error;
            }
            """
        )
        == []
    )


def test_memset_aggregate_before_field_use_is_silent():
    assert (
        _scan(
            """
            typedef struct { char *buffer; int length; } printbuffer;
            void f(void) {
                printbuffer buffer[1];
                memset(buffer, 0, sizeof(buffer));
                buffer[0].length = 1;
                (void)buffer[0].buffer;
            }
            """
        )
        == []
    )


def test_definite_helper_outparam_still_silent_conditional_still_reported():
    safe = _scan(
        """
        void initialize(int *out) { *out = 7; }
        int f(void) {
            int value;
            initialize(&value);
            return value;
        }
        """
    )
    unsafe = _scan(
        """
        void initialize(int *out, int cond) { if (cond) *out = 7; }
        int f(int cond) {
            int value;
            initialize(&value, cond);
            return value;
        }
        """
    )
    assert safe == []
    assert len(unsafe) == 1


def test_sizeof_array_in_loop_condition_is_not_a_use():
    """sizeof(buf) must not count as reading uninitialized buffer contents."""
    assert (
        _scan(
            """
            int f(const unsigned char *in) {
                unsigned char number_c_string[64];
                int i = 0;
                for (i = 0; (i < (sizeof(number_c_string) - 1)); i++) {
                    number_c_string[i] = in[i];
                }
                number_c_string[i] = '\\0';
                return (int)number_c_string[0];
            }
            """
        )
        == []
    )


def test_uninitialized_pointer_passed_to_sink_still_reported():
    """Bare pointer args are uses of the pointer, not callee out-params."""
    issues = _scan(
        """
        static void sink(int *ptr) { *ptr = 10; }
        void bad(void) {
            int *ptr;
            sink(ptr);
        }
        """
    )
    assert len(issues) == 1
    assert "ptr" in issues[0].message
