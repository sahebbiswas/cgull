"""Regression coverage for balanced regex-fallback function declarators (#443)."""

from unittest.mock import patch

from cgull.ast_analyzer import CASTParser


def _parse_fallback(source: str, *, line_map=None):
    parser = CASTParser()
    with patch.object(
        parser,
        "_try_pycparser",
        return_value=(None, False, "regex-fallback"),
    ):
        ctx = parser.parse(source, line_map=line_map)
    assert not ctx.has_pycparser
    return ctx


def test_thread_shaped_function_pointer_definition_is_not_lost():
    source = """HANDLE create_thread(
    HANDLE (*start_routine)(HANDLE),
    HANDLE args)
{
    HANDLE thread = start_routine(args);
    return thread;
}

void wait_for_thread(HANDLE thread)
{
    (void)thread;
}
"""

    ctx = _parse_fallback(source)

    assert [fn.name for fn in ctx.functions] == ["create_thread", "wait_for_thread"]
    create_thread = ctx.functions[0]
    assert (create_thread.start_line_exp, create_thread.body_start_line_exp, create_thread.end_line_exp) == (1, 4, 7)
    assert [param.name for param in create_thread.parameters] == ["start_routine", "args"]
    assert create_thread.parameters[0].is_pointer
    assert "start_routine(args)" in create_thread.body


def test_nested_function_pointer_parameter_commas_split_only_at_outer_depth():
    source = """int execute(
    int (*handler)(int, void (*nested)(char, long)),
    char buffer[16],
    int count)
{
    return handler(count, 0);
}
"""

    fn = _parse_fallback(source).functions[0]

    assert [param.name for param in fn.parameters] == ["handler", "buffer", "count"]
    assert fn.parameters[0].is_pointer
    assert "nested" in fn.parameters[0].type_name
    assert fn.parameters[1].is_array


def test_multiline_pointer_return_and_attributes_preserve_mapped_coordinates():
    source = """const char *
lookup(
    const char *key
)
__attribute__((nonnull(1)))
{
    return key;
}
"""
    line_map = {line: line + 100 for line in range(1, 9)}

    fn = _parse_fallback(source, line_map=line_map).functions[0]

    assert fn.name == "lookup"
    assert fn.return_type == "const char *"
    assert (fn.start_line_exp, fn.body_start_line_exp, fn.end_line_exp) == (1, 6, 8)
    assert (fn.start_line, fn.body_start_line, fn.end_line) == (101, 106, 108)


def test_prototypes_calls_macro_invocations_and_control_flow_are_not_functions():
    source = """int prototype(int (*callback)(int));
WRAP(not_a_function)
int real(int value)
{
    const char *literal_brace = "}";
    if (value) {
        callback(value);
    }
    return value;
}
"""

    ctx = _parse_fallback(source)

    assert [fn.name for fn in ctx.functions] == ["real"]
    assert ctx.functions[0].end_line_exp == 10
    assert 'literal_brace = "}"' in ctx.functions[0].body


def test_qualifier_only_implicit_int_definitions_preserve_legacy_fallback():
    source = """static legacy_static(void)
{
    return 1;
}

inline legacy_inline()
{
    return 2;
}
"""

    ctx = _parse_fallback(source)

    assert [fn.name for fn in ctx.functions] == ["legacy_static", "legacy_inline"]
    assert [fn.return_type for fn in ctx.functions] == ["static", "inline"]
