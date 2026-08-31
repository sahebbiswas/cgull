"""Regression coverage for CGULL-007 heap-capacity data flow."""

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import ArrayIndexOutOfBoundsRule


def test_heap_capacity_dataflow_is_path_safe_and_preserves_alias_offsets():
    code = """
    typedef int wchar_t;

    void bad_cumulative_alias_offsets(void) {
        char *data = malloc(10);
        char *first = data + 2;
        char *second = first + 3;
        second[5] = 0;
    }

    void bad_compatible_branch_allocations(int select_first) {
        char *data;
        if (select_first) {
            data = malloc(10);
        } else {
            data = calloc(2, 5);
        }
        data[10] = 0;
    }

    void good_conditional_allocation_is_not_a_capacity_fact(int enabled) {
        char *data;
        if (enabled) {
            data = malloc(10);
        }
        data[10] = 0;
    }

    void good_assignment_kills_old_capacity(char *external) {
        char *data = malloc(10);
        data = external;
        data[10] = 0;
    }

    void bad_int_pointee_capacity(void) {
        int *data = malloc(10 * sizeof(int));
        data[10] = 0;
    }

    void bad_wchar_pointee_capacity(void) {
        wchar_t *data = malloc(10);
        data[2] = 0;
    }
    """
    ctx = CASTParser().parse(code)
    issues = ArrayIndexOutOfBoundsRule().scan_ast("test.c", ctx)

    reported_functions = {
        fn.name
        for issue in issues
        for fn in ctx.functions
        if fn.start_line <= issue.line_number <= fn.end_line
    }
    assert {
        "bad_cumulative_alias_offsets",
        "bad_compatible_branch_allocations",
        "bad_int_pointee_capacity",
        "bad_wchar_pointee_capacity",
    } <= reported_functions
    assert "good_conditional_allocation_is_not_a_capacity_fact" not in reported_functions
    assert "good_assignment_kills_old_capacity" not in reported_functions


def test_element_size_uses_exact_pointee_types():
    rule = ArrayIndexOutOfBoundsRule()
    assert rule._element_size("char *") == 1
    assert rule._element_size("char16_t *") == 2
    assert rule._element_size("char32_t *") == 4
    assert rule._element_size("wchar_t *") == 4
    assert rule._element_size("character_record *") is None


def test_regex_alias_walk_accumulates_offsets_and_stops_at_assignment_kills():
    rule = ArrayIndexOutOfBoundsRule()
    source_lines = [
        "void test(void) {",
        "    char storage[10];",
        "    char *first = storage + 2;",
        "    char *second = first + 3;",
        "    second[5] = 0;",
        "}",
    ]
    issues = rule.scan_line("test.c", 5, source_lines[4], "\n".join(source_lines), source_lines)
    assert len(issues) == 1

    source_lines[4] = "    second = external;"
    source_lines.insert(5, "    second[5] = 0;")
    issues = rule.scan_line("test.c", 6, source_lines[5], "\n".join(source_lines), source_lines)
    assert not issues
