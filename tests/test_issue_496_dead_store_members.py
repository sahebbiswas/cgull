"""Regression coverage for issue #496 direct aggregate member dead stores."""

from pycparser import c_parser

from cgull.cfg import build_cfg
from cgull.cfg.expression_effects import ordered_expression_effects, ordered_storage_effects
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


_PARSER = c_parser.CParser()


def _func(source: str, name: str = "f"):
    ast = _PARSER.parse(source)
    return next(
        ext
        for ext in ast.ext
        if type(ext).__name__ == "FuncDef" and ext.decl.name == name
    )


def _dead_store_lines(source: str):
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-042")],
        engine_mode=AnalysisEngine.HYBRID,
    )
    return {
        issue.line_number
        for issue in scanner.scan_text(source, "issue_496.c").issues
        if issue.rule_id == "CGULL-042"
    }


def test_storage_effect_keeps_direct_member_identity_without_scalar_write():
    func = _func("struct S { int field; }; void f(void) { struct S s; s.field = 1; }")
    assignment = func.body.block_items[1]

    # Preserve #464: the shared scalar CFG contract still sees an indirect write.
    assert ordered_expression_effects(assignment) == (("indirect_write", None),)

    effects = ordered_storage_effects(assignment)
    assert len(effects) == 1
    effect = effects[0]
    assert effect.action == "write"
    assert effect.root == "s"
    assert effect.member_path == ("field",)
    assert effect.access_path == (".",)
    assert effect.write_kind == "plain"
    assert effect.is_direct_subobject

    cfg = build_cfg(func)
    cfg_assignment = next(node for node in cfg.nodes.values() if node.kind == "assignment")
    assert cfg_assignment.writes == set()


def test_storage_effect_preserves_pointer_member_distinction():
    func = _func("struct S { int field; }; void f(struct S *p) { p->field = 1; }")
    assignment = func.body.block_items[0]
    effects = ordered_storage_effects(assignment)

    member_write = next(effect for effect in effects if effect.action == "write")
    assert member_write.root == "p"
    assert member_write.member_path == ("field",)
    assert member_write.access_path == ("->",)
    assert not member_write.is_direct_subobject


def test_single_direct_member_store_is_reported():
    source = """struct S { int a; int b; };
void f(void) {
    struct S data;
    data.a = 0;
}
"""

    assert 4 in _dead_store_lines(source)


def test_same_member_read_keeps_direct_member_store_live():
    source = """struct S { int a; int b; };
int f(void) {
    struct S data;
    data.a = 0;
    return data.a;
}
"""

    assert 4 not in _dead_store_lines(source)


def test_unrelated_member_read_does_not_keep_store_live():
    source = """struct S { int a; int b; };
int f(void) {
    struct S data;
    data.a = 1;
    data.b = 2;
    return data.b;
}
"""

    dead_lines = _dead_store_lines(source)
    assert 4 in dead_lines
    assert 5 not in dead_lines


def test_nested_direct_member_store_is_reported():
    source = """struct Inner { int value; };
struct Outer { struct Inner inner; };
void f(void) {
    struct Outer data;
    data.inner.value = 1;
}
"""

    assert 5 in _dead_store_lines(source)


def test_compound_member_update_reads_prior_member_value():
    source = """struct S { int a; };
int f(void) {
    struct S data;
    data.a = 1;
    data.a += 2;
    return data.a;
}
"""

    dead_lines = _dead_store_lines(source)
    assert 4 not in dead_lines
    assert 5 not in dead_lines


def test_multiple_member_dead_stores_are_reported_without_whole_object_finding():
    source = """struct S { int a; int b; };
void f(void) {
    struct S data;
    data.a = 1;
    data.b = 2;
}
"""

    dead_lines = _dead_store_lines(source)
    assert 3 not in dead_lines
    assert {4, 5}.issubset(dead_lines)


def test_pointer_member_store_is_not_treated_as_direct_local_member_store():
    source = """struct S { int a; };
struct S *get_s(void);
void f(void) {
    struct S *p = get_s();
    p->a = 1;
}
"""

    assert 5 not in _dead_store_lines(source)


def test_volatile_member_write_is_observable():
    source = """struct S { volatile int status; };
void f(void) {
    struct S data;
    data.status = 1;
}
"""

    assert 4 not in _dead_store_lines(source)


def test_reading_sibling_union_member_consumes_write():
    source = """union U { int bits; float value; };
int f(void) {
    union U data;
    data.bits = 0x3f800000;
    return data.value == 1.0f;
}
"""

    assert 4 not in _dead_store_lines(source)
