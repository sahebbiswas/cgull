"""CGULL-042 regressions for join-aware if/else dead-store liveness (#554)."""

from tests.test_dead_stores import (
    issue_lines,
    scan_dead_stores_fallback,
    scan_with_rule,
)


def _assert_cfg_and_fallback_lines(code: str, expected_lines: set[int]) -> None:
    cfg_issues = scan_with_rule("CGULL-042", code)
    fallback_issues = scan_dead_stores_fallback(code)

    assert issue_lines(cfg_issues) == expected_lines
    assert issue_lines(fallback_issues) == expected_lines


def test_if_else_assign_then_use_after_join_is_not_dead():
    code = """void f(int cond) {
    int x;
    if (cond) {
        x = 1;
    } else {
        x = 2;
    }
    consume(x);
}
"""

    _assert_cfg_and_fallback_lines(code, set())


def test_else_if_chain_assign_then_use_after_join_is_not_dead():
    code = """void f(int n) {
    int length;
    if (n < 0) {
        length = sprintf(buf, "%d", n);
    } else if (n == 0) {
        length = sprintf(buf, "%u", 0u);
    } else {
        length = sprintf(buf, "%g", (double)n);
    }
    print_buffer(buf, length);
}
"""

    _assert_cfg_and_fallback_lines(code, set())


def test_if_without_else_prior_store_still_live_after_join():
    code = """void f(int cond) {
    int x;
    x = 1;
    if (cond) {
        x = 2;
    }
    consume(x);
}
"""

    _assert_cfg_and_fallback_lines(code, set())


def test_nested_if_may_overwrite_keeps_outer_arm_store_live():
    code = """void f(int c, int d) {
    int length;
    if (c) {
        length = 1;
    } else {
        length = 2;
        if (d) {
            length = 3;
        }
    }
    consume(length);
}
"""

    _assert_cfg_and_fallback_lines(code, set())


def test_true_dead_store_overwrite_still_reported():
    code = """void f(void) {
    int x;
    x = 1;
    x = 2;
    consume(x);
}
"""

    _assert_cfg_and_fallback_lines(code, {3})


def test_both_arms_overwritten_after_join_still_reported():
    code = """void f(int cond) {
    int x;
    if (cond) {
        x = 1;
    } else {
        x = 2;
    }
    x = 3;
    consume(x);
}
"""

    _assert_cfg_and_fallback_lines(code, {4, 6})


def test_same_arm_overwrite_before_join_still_reported():
    code = """void f(int cond) {
    int x = 0;
    if (cond) {
        x = 1;
        x = 2;
    }
    consume(x);
}
"""

    _assert_cfg_and_fallback_lines(code, {4})


def test_loop_walk_pointer_update_is_not_dead():
    code = """void walk(node_t *child) {
    node_t *next = NULL;
    while (child != NULL) {
        node_t *newchild = duplicate(child);
        if (next != NULL) {
            next->next = newchild;
            next = newchild;
        } else {
            next = newchild;
        }
        child = child->next;
    }
}
"""

    issues = scan_dead_stores_fallback(code)
    # The carried `next = newchild` stores must not be reported.
    assert not any("next =" in (issue.code_snippet or "") for issue in issues)
