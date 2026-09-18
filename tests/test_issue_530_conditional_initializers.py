"""CGULL-042 regressions for conditional and macro-expanded overwrites (#530)."""

import pytest

from cgull.ast_analyzer import CASTParser
from cgull.models import ParseTier
from cgull.rules import get_rule_by_id


def scan(source, *, fallback=False):
    context = CASTParser().parse(source)
    assert context.has_pycparser
    if fallback:
        context.has_pycparser = False
        context.pycparser_ast = None
    issues = get_rule_by_id("CGULL-042").scan_ast("test.c", context)
    return context, issues


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("keyword,callee", [("if", "api"), ("while", "next_value")])
def test_pure_initializer_overwritten_in_next_condition(keyword, callee, fallback):
    source = "\n".join([
        "void f(void) {",
        "    int rc = 0;",
        f"    {keyword} ((rc = {callee}()) != 0) {{",
        "        use(rc);",
        "    }",
        "    use(rc);",
        "}",
    ])
    _, issues = scan(source, fallback=fallback)
    assert issues == []


@pytest.mark.parametrize("fallback", [False, True])
def test_post_declaration_dead_store_before_conditional_overwrite_remains(fallback):
    source = "\n".join([
        "void f(void) {",
        "    int rc;",
        "    rc = first();",
        "    if ((rc = second()) != 0) {",
        "        use(rc);",
        "    }",
        "    use(rc);",
        "}",
    ])
    _, issues = scan(source, fallback=fallback)
    assert {issue.line_number for issue in issues} == {3}


@pytest.mark.parametrize("fallback", [False, True])
def test_effectful_initializer_before_conditional_overwrite_remains(fallback):
    source = "\n".join([
        "void f(void) {",
        "    int rc = initialize_device();",
        "    if ((rc = api()) != 0) {",
        "        use(rc);",
        "    }",
        "    use(rc);",
        "}",
    ])
    _, issues = scan(source, fallback=fallback)
    assert {issue.line_number for issue in issues} == {2}


def test_file_scope_enum_initializer_is_proven_pure():
    source = "\n".join([
        "enum Status { OS_SUCCESS = 0, OS_FAILURE = 1 };",
        "void f(int flag) {",
        "    int rc = OS_SUCCESS;",
        "    if ((rc = api()) != OS_SUCCESS) {",
        "        use(rc);",
        "    }",
        "    use(rc);",
        "}",
    ])
    _, issues = scan(source)
    assert issues == []


def test_shadowed_enum_name_remains_conservative():
    source = "\n".join([
        "enum Status { OS_SUCCESS = 0, OS_FAILURE = 1 };",
        "void f(void) {",
        "    int OS_SUCCESS = initialize_device();",
        "    use(OS_SUCCESS);",
        "    int rc = OS_SUCCESS;",
        "    if ((rc = api()) != 0) {",
        "        use(rc);",
        "    }",
        "    use(rc);",
        "}",
    ])
    _, issues = scan(source)
    assert {issue.line_number for issue in issues} == {5}


def _macro_source(initializer):
    return "\n".join([
        "enum Status { OS_SUCCESS = 0, OS_FAILURE = 1 };",
        "#define CHECK(call) do { \\",
        f"    int rc = {initializer}; \\",
        "    if ((rc = (call)) != OS_SUCCESS) { \\",
        "        use(rc); \\",
        "    } \\",
        "} while (0)",
        "void f(void) {",
        "    CHECK(api());",
        "}",
    ])


def test_macro_expanded_enum_initializer_is_suppressed():
    source = _macro_source("OS_SUCCESS")
    context, issues = scan(source)
    assert context.parse_tier == ParseTier.PCPP_PYCPARSER.value
    assert issues == []


def test_macro_effectful_initializer_keeps_invocation_provenance():
    source = _macro_source("initialize_device()")
    invocation_line = next(
        line
        for line, text in enumerate(source.splitlines(), 1)
        if "CHECK(api())" in text
    )
    context, issues = scan(source)
    assert context.parse_tier == ParseTier.PCPP_PYCPARSER.value
    assert len(issues) == 1
    assert issues[0].line_number == invocation_line
    assert issues[0].code_snippet == "CHECK(api());"
