"""Regression coverage for issue #464 CFG read/write semantics."""

import pytest
from pycparser import c_parser

from cgull.cfg import Initialization, build_cfg
from cgull.cfg.expression_effects import ordered_expression_effects
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


def _node(cfg, *, kind: str = None, expr: str = None):
    matches = [
        node
        for node in cfg.nodes.values()
        if (kind is None or node.kind == kind)
        and (expr is None or node.expr_str == expr)
    ]
    assert len(matches) == 1, [(node.kind, node.expr_str) for node in matches]
    return matches[0]


def _dead_store_lines(source: str):
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-042")],
        engine_mode=AnalysisEngine.HYBRID,
    )
    return {
        issue.line_number
        for issue in scanner.scan_text(source, "issue_464.c").issues
        if issue.rule_id == "CGULL-042"
    }


def test_plain_assignment_does_not_read_previous_lhs_value():
    cfg = build_cfg(_func("void f(int x, int y) { x = y; }"))
    assignment = _node(cfg, kind="assignment", expr="x = y")

    assert assignment.reads == {"y"}
    assert assignment.writes == {"x"}


def test_uninitialized_declaration_remains_non_write():
    cfg = build_cfg(_func("void f(void) { int x; return; }"))
    declaration = next(node for node in cfg.nodes.values() if node.kind == "decl")

    assert declaration.reads == set()
    assert declaration.writes == set()


def test_top_level_deallocator_retains_existing_lifetime_event_contract():
    cfg = build_cfg(_func("void free(void *); void f(int *p) { free(p); }"))
    free_event = _node(cfg, kind="free")

    assert free_event.reads == set()
    assert free_event.freed == {"p"}


@pytest.mark.parametrize(
    "operator",
    ["+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="],
)
def test_all_compound_assignments_read_and_write_direct_scalar_target(operator):
    cfg = build_cfg(_func(f"void f(int x, int y) {{ x {operator} y; }}"))
    assignment = next(node for node in cfg.nodes.values() if node.kind == "assignment")

    assert assignment.reads == {"x", "y"}
    assert assignment.writes == {"x"}


@pytest.mark.parametrize("expression", ["++x", "x++", "--x", "x--"])
def test_pre_and_post_mutation_read_and_write_direct_scalar(expression):
    cfg = build_cfg(_func(f"void f(int x) {{ {expression}; }}"))
    mutation = next(node for node in cfg.nodes.values() if node.kind == "unaryop")

    assert mutation.reads == {"x"}
    assert mutation.writes == {"x"}


def test_direct_struct_member_mutation_reads_aggregate_without_scalar_write():
    func = _func("void f(void) { struct S { int field; } s; s.field++; }")
    mutation_ast = func.body.block_items[1]

    assert ordered_expression_effects(mutation_ast) == (
        ("read", "s"),
        ("indirect_write", None),
    )

    cfg = build_cfg(func)
    mutation = next(node for node in cfg.nodes.values() if node.kind == "unaryop")
    assert mutation.reads == {"s"}
    assert mutation.writes == set()


def test_nested_direct_member_plain_store_does_not_read_root_aggregate():
    func = _func(
        "struct Inner { int c; }; "
        "struct Outer { struct Inner b; }; "
        "void f(void) { struct Outer a; a.b.c = 1; }"
    )
    assignment_ast = func.body.block_items[1]

    assert ordered_expression_effects(assignment_ast) == (("indirect_write", None),)

    cfg = build_cfg(func)
    assignment = next(node for node in cfg.nodes.values() if node.kind == "assignment")
    assert assignment.reads == set()
    assert assignment.writes == set()


def test_nested_direct_member_compound_store_reads_root_aggregate():
    func = _func(
        "struct Inner { int c; }; "
        "struct Outer { struct Inner b; }; "
        "void f(void) { struct Outer a; a.b.c += 1; }"
    )
    assignment_ast = func.body.block_items[1]

    assert ordered_expression_effects(assignment_ast) == (
        ("read", "a"),
        ("indirect_write", None),
    )

    cfg = build_cfg(func)
    assignment = next(node for node in cfg.nodes.values() if node.kind == "assignment")
    assert assignment.reads == {"a"}
    assert assignment.writes == set()


def test_lvalue_side_effects_are_ordered_and_indirect_store_is_not_scalar_write():
    func = _func(
        "int helper(int); "
        "void f(int *a, int i, int x) { a[i++] += helper(x); }"
    )
    assignment_ast = func.body.block_items[0]

    assert ordered_expression_effects(assignment_ast) == (
        ("read", "a"),
        ("read", "i"),
        ("write", "i"),
        ("read", "helper"),
        ("read", "x"),
        ("indirect_write", None),
    )

    cfg = build_cfg(func)
    assignment = next(node for node in cfg.nodes.values() if node.kind == "assignment")
    assert {"a", "i", "x"}.issubset(assignment.reads)
    assert assignment.writes == {"i"}


def test_pointer_increment_in_lvalue_is_a_scalar_write_but_pointee_store_is_not():
    cfg = build_cfg(_func("void f(int *p, int value) { *p++ = value; }"))
    assignment = next(node for node in cfg.nodes.values() if node.kind == "assignment")

    assert assignment.reads == {"p", "value"}
    assert assignment.writes == {"p"}


@pytest.mark.parametrize(
    ("source", "node_kind"),
    [
        ("void f(int x) { if (x++) {} }", "if_cond"),
        ("void f(int x) { while (x++) {} }", "while_cond"),
        ("void f(int x) { do {} while (x++); }", "do_cond"),
        ("void f(int x) { for (; x++; ) {} }", "for_cond"),
        ("void f(int x) { switch (x++) { default: break; } }", "switch_cond"),
    ],
)
def test_control_predicates_use_same_mutation_semantics(source, node_kind):
    cfg = build_cfg(_func(source))
    condition = _node(cfg, kind=node_kind)

    assert condition.reads == {"x"}
    assert condition.writes == {"x"}


def test_legacy_dataflow_observes_unary_mutation_write():
    cfg = build_cfg(_func("void f(int x) { x++; return; }"))
    cfg.analyze_dataflow()
    ret = _node(cfg, kind="return")

    # Parameters are not pre-seeded in this low-level CFG query. The post-mutation
    # state therefore proves that the shared transfer function consumed x++ as a
    # write rather than a read-only event.
    assert cfg.query_initialization("x", ret.node_id) == Initialization.INITIALIZED


def test_cgull_042_keeps_compound_assignment_chain_live():
    source = """void consume(int value);
void f(int y) {
    int x = 1;
    x += y;
    x += 1;
    consume(x);
}
"""

    assert 4 not in _dead_store_lines(source)
    assert 5 not in _dead_store_lines(source)


def test_cgull_042_keeps_initializer_used_by_mutating_lvalue_live():
    source = """void consume(int value);
void f(int *a, int value) {
    int i = 0;
    a[i++] = value;
    consume(i);
}
"""

    assert 3 not in _dead_store_lines(source)


def test_cgull_042_oslog_style_varlen_compound_update_keeps_prior_value_live():
    source = """int compute_length(void);
void consume(int value);
void f(void) {
    int i = 0;
    int varLen = compute_length();
    varLen += 2;
    for (i = 0; i < varLen; i++) {
        consume(i);
    }
}
"""

    dead_lines = _dead_store_lines(source)
    assert 5 not in dead_lines
    assert 6 not in dead_lines
