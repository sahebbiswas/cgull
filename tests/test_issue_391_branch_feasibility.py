"""Regression coverage for impossible CGULL-049 branch joins (#391)."""

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


_PREAMBLE = """
typedef unsigned long size_t;
void *malloc(size_t size);
"""


def _scan(functions: str):
    ctx = CASTParser().parse(_PREAMBLE + functions)
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue_391.c", ctx)


def _cwes(functions: str):
    return [issue.cwe_id for issue in _scan(functions)]


def test_literal_branch_truth_excludes_impossible_range_join():
    assert _cwes("""
void f(void) {
    int n = -1;
    if (1) {
        n = 99;
    }
    malloc(n);
}
""") == []
    assert _cwes("""
void g(void) {
    int n = -1;
    if (0) {
    } else {
        n = 99;
    }
    malloc(n);
}
""") == []


def test_folded_constant_comparisons_exclude_impossible_branch():
    assert _cwes("""
void f(void) {
    int n = -1;
    if (2 > 1) {
        n = 99;
    }
    malloc(n);
}
""") == []
    assert _cwes("""
void g(void) {
    int n = -1;
    if (2 < 1) {
    } else {
        n = 99;
    }
    malloc(n);
}
""") == []


def test_folded_comparison_uses_c_signed_unsigned_conversions():
    # In C, -1 is converted to unsigned int here, so this condition is false.
    assert _cwes("""
void f(void) {
    int n = -1;
    if (-1 < 1U) {
        n = 99;
    }
    malloc(n);
}
""") == ["CWE-195"]


def test_tracked_local_constant_can_prove_branch_truth():
    assert _cwes("""
void f(void) {
    const int use_good = 1;
    int n = -1;
    if (use_good) {
        n = 99;
    }
    malloc(n);
}
""") == []


def test_unknown_condition_retains_negative_join_and_exact_cwe():
    assert _cwes("""
void f(int choose_good) {
    int n = -1;
    if (choose_good) {
        n = 99;
    }
    malloc(n);
}
""") == ["CWE-195"]
    assert _cwes("""
void g(int choose_good) {
    short n = -1;
    if (choose_good) {
        n = 99;
    }
    malloc(n);
}
""") == ["CWE-194"]


def test_reassigned_condition_does_not_keep_stale_constant_truth():
    assert _cwes("""
void f(int input) {
    int use_good = 1;
    int n = -1;
    use_good = input;
    if (use_good) {
        n = 99;
    }
    malloc(n);
}
""") == ["CWE-195"]


def test_address_escape_and_call_invalidate_condition_constant():
    assert _cwes("""
void mutate(int *value);
void f(void) {
    int use_good = 1;
    int n = -1;
    mutate(&use_good);
    if (use_good) {
        n = 99;
    }
    malloc(n);
}
""") == ["CWE-195"]


def test_globals_and_helper_conditions_remain_unknown():
    assert _cwes("""
int use_good = 1;
void f(void) {
    int n = -1;
    if (use_good) {
        n = 99;
    }
    malloc(n);
}
""") == ["CWE-195"]
    assert _cwes("""
int choose_good(void);
void g(void) {
    int n = -1;
    if (choose_good()) {
        n = 99;
    }
    malloc(n);
}
""") == ["CWE-195"]


def test_loop_join_does_not_manufacture_constant_truth():
    assert _cwes("""
void f(int enter_loop) {
    int use_good = 1;
    while (enter_loop) {
        use_good = 0;
        enter_loop = 0;
    }
    int n = -1;
    if (use_good) {
        n = 99;
    }
    malloc(n);
}
""") == ["CWE-195"]


def test_unresolved_control_flow_drops_branch_proof_facts():
    assert _cwes("""
void f(void) {
    int use_good = 1;
    int n = -1;
    goto missing;
    if (use_good) {
        n = 99;
    }
    malloc(n);
}
""") == ["CWE-195"]
