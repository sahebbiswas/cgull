"""CGULL-007 must prove bounds before each short-circuit access."""
import pytest

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import ArrayIndexOutOfBoundsRule


def scan(condition, *, kind="while", index_type="unsigned", body="data[A] = 0;\n++A;"):
    code = f"""#define MAX_LENGTH 16
char *data[16];
void f({index_type} A, unsigned limit, int enabled) {{
    {kind} ({condition}) {{
        {body}
    }}
}}
"""
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return ArrayIndexOutOfBoundsRule().scan_ast("issue_406.c", ctx)


@pytest.mark.parametrize("kind", ["while", "if"])
@pytest.mark.parametrize("condition,index_type", [
    ("A < MAX_LENGTH && data[A] != 0", "unsigned"),
    ("enabled && A < MAX_LENGTH && data[A]", "unsigned"),
    ("A >= 0 && A < MAX_LENGTH && data[A]", "int"),
    ("0 <= A && MAX_LENGTH > A && data[A]", "int"),
    ("A < MAX_LENGTH &&\n        data[A]", "unsigned"),
    ("A < MAX_LENGTH && (enabled || data[A])", "unsigned"),
])
def test_ordered_guards_protect_condition_and_body(kind, condition, index_type):
    assert scan(condition, kind=kind, index_type=index_type) == []


@pytest.mark.parametrize("kind", ["while", "if"])
@pytest.mark.parametrize("condition,index_type,lines", [
    ("data[A] && A < MAX_LENGTH", "unsigned", {4}),
    ("A < MAX_LENGTH + 1 && data[A]", "unsigned", {4, 5}),
    ("A <= MAX_LENGTH && data[A]", "unsigned", {4, 5}),
    ("A < MAX_LENGTH && data[A]", "int", {4, 5}),
    ("A < MAX_LENGTH || data[A]", "unsigned", {4, 5}),
    ("A < limit && data[A]", "unsigned", {4, 5}),
    ("A < 32 && data[A]", "unsigned", {4, 5}),
    ("A < -1 && data[A]", "unsigned", {4, 5}),
    ("A < MAX_LENGTH && data[A + 1]", "unsigned", {4}),
    ("A < MAX_LENGTH && ++A && data[A]", "unsigned", {4, 5}),
    ("A < MAX_LENGTH && mutate(&A) && data[A]", "unsigned", {4, 5}),
])
def test_unsafe_paths_remain_reportable(kind, condition, index_type, lines):
    assert {i.line_number for i in scan(condition, kind=kind, index_type=index_type)} == lines


def test_body_mutation_invalidates_guard():
    issues = scan("A < MAX_LENGTH && data[A]", body="++A;\n        data[A] = 0;")
    assert {i.line_number for i in issues} == {6}


def test_or_false_edge_guards_access_but_not_true_body():
    issues = scan("A >= MAX_LENGTH || data[A]")
    assert {i.line_number for i in issues} == {5}


def test_same_line_condition_and_body_have_distinct_events():
    code = "char *data[16]; void f(unsigned A) { if (data[A] && A < 16) { data[A] = 0; } }"
    issues = ArrayIndexOutOfBoundsRule().scan_ast("issue_406.c", CASTParser().parse(code))
    assert len(issues) == 1


def test_guarded_access_as_call_argument():
    assert scan("A < MAX_LENGTH && data[A]", kind="if", body="use(data[A]);") == []


def test_false_branch_does_not_inherit_true_guard():
    code = """char *data[16];
void f(unsigned A) {
    if (A < 16 && data[A]) {}
    else { data[A] = 0; }
    data[A] = 0;
}
"""
    issues = ArrayIndexOutOfBoundsRule().scan_ast("issue_406.c", CASTParser().parse(code))
    assert {i.line_number for i in issues} == {4, 5}


def test_loop_backedge_cannot_reuse_stale_guard():
    issues = scan("data[A] && A < MAX_LENGTH", body="++A;")
    assert {i.line_number for i in issues} == {4}


@pytest.mark.parametrize("effect", ["log_message();", "++A;"])
def test_switch_other_case_effects_do_not_erase_guard(effect):
    body = f"""switch (enabled) {{
        case 0: data[A] = 0; break;
        default: {effect} break;
    }}"""
    assert scan("A < MAX_LENGTH", kind="if", body=body) == []


@pytest.mark.parametrize("effect", ["log_message();", "++A;"])
def test_switch_later_effects_do_not_erase_guard(effect):
    body = f"""switch (data[A] != 0) {{
        case 0: data[A] = 0; {effect} break;
        default: break;
    }}"""
    assert scan("A < MAX_LENGTH", kind="if", body=body) == []


@pytest.mark.parametrize("selector", ["++A", "mutate(&A)"])
def test_switch_selector_effects_still_invalidate_guard(selector):
    body = f"""switch ({selector}) {{
        case 0: data[A] = 0; break;
        default: break;
    }}"""
    issues = scan("A < MAX_LENGTH", kind="if", body=body)
    assert len(issues) == 1
    assert issues[0].line_number == 6


def test_switch_case_mutation_still_invalidates_guard():
    body = """switch (enabled) {
        case 0: ++A;
        default: data[A] = 0; break;
    }"""
    issues = scan("A < MAX_LENGTH", kind="if", body=body)
    assert len(issues) == 1
    assert issues[0].line_number == 7
