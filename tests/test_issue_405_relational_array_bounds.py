"""Focused regression tests for issue #405 / CGULL-007."""

from pycparser import c_ast

from cgull.ast_analyzer import CASTParser
from cgull.cfg.affine_relations import AffineFacts
from cgull.rules.types_and_arrays import ArrayIndexOutOfBoundsRule


def _scan(code: str):
    ctx = CASTParser().parse(code)
    return ArrayIndexOutOfBoundsRule().scan_ast("issue_405.c", ctx)


def _cgull_007(code: str):
    return [issue for issue in _scan(code) if issue.rule_id == "CGULL-007"]


def test_lockstep_while_induction_proves_index_bound():
    code = """
    void f(void) {
        int data[16];
        unsigned i = 0;
        unsigned y = 0;
        while (y < 16) {
            data[i] = 0;
            ++i;
            ++y;
        }
    }
    """
    assert _cgull_007(code) == []


def test_lockstep_for_induction_proves_index_bound():
    code = """
    void f(void) {
        int data[16];
        unsigned i = 0;
        for (unsigned y = 0; y < 16; y += 1) {
            data[i] = 0;
            i += 1;
        }
    }
    """
    assert _cgull_007(code) == []


def test_constant_offset_relation_translates_upper_bound():
    code = """
    void f(void) {
        int data[16];
        unsigned y = 0;
        unsigned i = y + 1;
        while (y < 15) {
            data[i] = 0;
            ++i;
            ++y;
        }
    }
    """
    assert _cgull_007(code) == []


def test_divergent_updates_do_not_suppress():
    code = """
    void f(void) {
        int data[16];
        unsigned i = 0;
        unsigned y = 0;
        while (y < 16) {
            data[i] = 0;
            i += 2;
            y += 1;
        }
    }
    """
    assert _cgull_007(code)


def test_conditional_index_update_does_not_suppress():
    code = """
    void f(int cond) {
        int data[16];
        unsigned i = 0;
        unsigned y = 0;
        while (y < 16) {
            if (cond) ++i;
            data[i] = 0;
            ++y;
        }
    }
    """
    assert _cgull_007(code)


def test_reassignment_breaking_relation_does_not_suppress():
    code = """
    void f(void) {
        int data[16];
        unsigned i = 0;
        unsigned y = 0;
        while (y < 16) {
            i = y + 2;
            data[i] = 0;
            ++i;
            ++y;
        }
    }
    """
    assert _cgull_007(code)


def test_translated_bound_must_fit_capacity():
    code = """
    void f(void) {
        int data[16];
        unsigned y = 0;
        unsigned i = y + 1;
        while (y < 16) {
            data[i] = 0;
            ++i;
            ++y;
        }
    }
    """
    assert _cgull_007(code)


def test_signed_index_still_requires_lower_bound_proof():
    code = """
    void f(int start) {
        int data[16];
        int i = start;
        int y = start;
        while (y < 16) {
            data[i] = 0;
            ++i;
            ++y;
        }
    }
    """
    assert _cgull_007(code)


def test_assignment_from_self_does_not_record_self_relation():
    facts = AffineFacts().assign("i", c_ast.Constant("int", "0"))
    rhs = c_ast.BinaryOp("+", c_ast.ID("i"), c_ast.Constant("int", "1"))

    updated = facts.assign("i", rhs)

    assert all(first != second for first, second, _ in updated.relations)
