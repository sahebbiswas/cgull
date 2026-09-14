"""Regression coverage for fallback global-scope classification (#445)."""

from cgull.ast_analyzer import CASTParser
from cgull.models import ParseTier
from cgull.rules import get_rule_by_id


def _force_regex_fallback(parser: CASTParser, missed_functions=()):
    """Force fallback and optionally simulate functions the extractor missed."""
    real_extract_functions = parser._extract_functions
    missed = set(missed_functions)

    parser._try_pycparser = lambda clean_code, defined_syms=None: (
        None,
        False,
        ParseTier.REGEX_FALLBACK.value,
    )

    def extract_functions(lines, full_code, custom_typedefs=None, line_map=None):
        return [
            fn
            for fn in real_extract_functions(
                lines,
                full_code,
                custom_typedefs=custom_typedefs,
                line_map=line_map,
            )
            if fn.name not in missed
        ]

    parser._extract_functions = extract_functions


def test_fallback_missed_function_local_does_not_become_global_or_shadow_parameter():
    code = """PLATFORM_HANDLE create_thread(
    PLATFORM_HANDLE (*start_routine)(PLATFORM_HANDLE),
    PLATFORM_HANDLE args)
{
    platform_thread_t *thread_object;
    return thread_object;
}

void wait_for_thread(PLATFORM_HANDLE thread_object)
{
    (void)thread_object;
}
"""
    parser = CASTParser()
    _force_regex_fallback(parser, missed_functions={"create_thread"})

    ast_ctx = parser.parse(code)

    assert ast_ctx.parse_tier == ParseTier.REGEX_FALLBACK.value
    assert [fn.name for fn in ast_ctx.functions] == ["wait_for_thread"]
    assert "thread_object" not in ast_ctx.global_variables

    issues = get_rule_by_id("CGULL-043").scan_ast("thread.c", ast_ctx)
    assert issues == []


def test_fallback_genuine_file_scope_global_still_shadows_parameter():
    code = """PLATFORM_HANDLE thread_object;

void wait_for_thread(PLATFORM_HANDLE thread_object)
{
    (void)thread_object;
}
"""
    parser = CASTParser()
    _force_regex_fallback(parser)

    ast_ctx = parser.parse(code)

    assert "thread_object" in ast_ctx.global_variables
    issues = get_rule_by_id("CGULL-043").scan_ast("thread.c", ast_ctx)
    assert len(issues) == 1
    assert "Parameter 'thread_object'" in issues[0].message
    assert "shadows global variable 'thread_object'" in issues[0].message


def test_fallback_globals_require_lexical_file_scope_even_without_function_ranges():
    code = (
        "#define DECL_BLOCK(x) do { \\\n"
        "    int macro_local = (x); \\\n"
        "} while (0)\n"
        "\n"
        "struct Demo {\n"
        "    int member;\n"
        "};\n"
        "\n"
        "int real_global = 1;\n"
        "const char *brace_text = \"{ not scope }\";\n"
        "char brace_char = '}';\n"
        "/* a comment with unmatched braces {{{ */\n"
        "int after_literals = 2;\n"
        "\n"
        "void intentionally_unrecognized(void)\n"
        "{\n"
        "    int local_value = 3;\n"
        "    struct Demo local_compound = (struct Demo){ .member = 4 };\n"
        "    if (local_value) {\n"
        "        int nested_value = 5;\n"
        "        (void)nested_value;\n"
        "    }\n"
        "}\n"
        "\n"
        "#if 0\n"
        "{\n"
        "    int inactive_value = 6;\n"
        "}\n"
        "#endif\n"
        "int after_inactive = 7;\n"
    )
    parser = CASTParser()
    _force_regex_fallback(parser, missed_functions={"intentionally_unrecognized"})

    ast_ctx = parser.parse(code)

    assert set(ast_ctx.global_variables) == {
        "real_global",
        "brace_text",
        "brace_char",
        "after_literals",
        "after_inactive",
    }
    for nested_name in (
        "macro_local",
        "member",
        "local_value",
        "local_compound",
        "nested_value",
        "inactive_value",
    ):
        assert nested_name not in ast_ctx.global_variables


def test_fallback_scope_tracks_unexpanded_brace_macros():
    code = (
        "#define OPEN_SCOPE {\n"
        "#define CLOSE_SCOPE }\n"
        "#define OPEN_SCOPE_FN() {\n"
        "#define CLOSE_SCOPE_FN() }\n"
        "void macro_body(void) OPEN_SCOPE\n"
        "    int macro_body_local = 1;\n"
        "    if (macro_body_local) OPEN_SCOPE_FN()\n"
        "        int nested_macro_local = 2;\n"
        "    CLOSE_SCOPE_FN()\n"
        "CLOSE_SCOPE\n"
        "int real_global_after_macros = 3;\n"
    )
    parser = CASTParser()
    _force_regex_fallback(parser, missed_functions={"macro_body"})

    ast_ctx = parser.parse(code)

    assert set(ast_ctx.global_variables) == {"real_global_after_macros"}
    assert "macro_body_local" not in ast_ctx.global_variables
    assert "nested_macro_local" not in ast_ctx.global_variables


def test_fallback_global_scope_preserves_line_mapping():
    parser = CASTParser()
    _force_regex_fallback(parser)

    ast_ctx = parser.parse("int mapped_global;\n", line_map={1: 101})

    assert ast_ctx.global_variables["mapped_global"].declaration_line == 101
