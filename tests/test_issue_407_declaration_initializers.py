"""Declaration initialization policy, exercised through both CGULL-042 tiers."""

import pytest

from cgull.ast_analyzer import CASTParser
from cgull.rules import get_rule_by_id


def scan(code, fallback):
    parser = CASTParser()
    if fallback == "regex":
        parser._try_pycparser = lambda *args, **kwargs: (None, False, "regex-fallback")
    context = parser.parse(code)
    if fallback:
        context.has_pycparser = False
        context.pycparser_ast = None
    else:
        assert context.has_pycparser
    return {issue.line_number for issue in get_rule_by_id("CGULL-042").scan_ast("test.c", context)}


@pytest.mark.parametrize("fallback", [False, True, "regex"])
@pytest.mark.parametrize("declaration,assignment", [
    ("int x = -1;", "x = api();"),
    ("int *x = NULL;", "x = get_pointer();"),
    ("struct S x = {0};", "x = get_value();"),
    ("int x = (1 + 2) * 3;", "x = api();"),
    ("int *x = &global;", "x = get_pointer();"),
])
def test_defensive_initialization(fallback, declaration, assignment):
    code = "\n".join([
        "#define NULL ((void *)0)",
        "struct S { int field; }; int global;",
        "void f(void) {", declaration, assignment, "use(x);", "}",
    ])
    assert scan(code, fallback) == set()


@pytest.mark.parametrize("fallback", [False, True, "regex"])
@pytest.mark.parametrize("initializer", ["initialize_device()", "++global", "(global = 1)", "global", "initialize_device() ? 1 : 0"])
def test_unproven_or_effectful_initializers_remain(fallback, initializer):
    code = "\n".join([
        "volatile int global;", "void f(void) {", f"int x = {initializer};",
        "x = api();", "use(x);", "}",
    ])
    assert 3 in scan(code, fallback)


@pytest.mark.parametrize("fallback", [False, True, "regex"])
def test_later_dead_assignment(fallback):
    code = "void f(void) {\nint x = 0;\nx = 1;\nx = 2;\nuse(x);\n}"
    assert scan(code, fallback) == {3}


@pytest.mark.parametrize("fallback", [False, True, "regex"])
def test_first_assignment_is_not_initialization(fallback):
    code = "void f(void) {\nint x;\nx = compute();\nx = 0;\nuse(x);\n}"
    assert scan(code, fallback) == {3}


@pytest.mark.parametrize("fallback", [False, True, "regex"])
def test_scope_exit_is_still_dead(fallback):
    assert 2 in scan("void f(void) {\nint x = 0;\n}", fallback)


@pytest.mark.parametrize("fallback", [False, True, "regex"])
def test_optional_overwrite_does_not_hide_unused_initializer(fallback):
    code = "void f(int flag) {\nint x = 0;\nif (flag) {\nx = 1;\n}\n}"
    assert 2 in scan(code, fallback)


def test_cfg_all_branches_overwrite():
    code = "void f(int flag) {\nint x = 0;\nif (flag) x = 1;\nelse x = 2;\nuse(x);\n}"
    assert scan(code, False) == set()


def test_cfg_same_line_later_assignment_is_not_suppressed():
    code = "void f(void) {\nint x = 0; x = 1;\nx = 2;\nuse(x);\n}"
    assert scan(code, False) == {2}


def test_cfg_early_exit_retains_initializer():
    code = "void f(int flag) {\nint x = 0;\nif (flag) return;\nx = 1;\nuse(x);\n}"
    assert 2 in scan(code, False)
