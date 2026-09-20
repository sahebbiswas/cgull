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


def test_comment_between_brace_and_else_keeps_join_live():
    """Comments between `}` and `else` must not break exclusive-arm parsing."""
    code = """void f(int cond) {
    int x;
    if (cond) {
        x = 1;
    } /* exclusive arm */ else {
        x = 2;
    }
    consume(x);
}
"""

    _assert_cfg_and_fallback_lines(code, set())


def test_comment_between_else_and_if_keeps_join_live():
    """Comments between `else` and `if` must still parse as else-if."""
    code = """void f(int n) {
    int length;
    if (n < 0) {
        length = 1;
    } else /* next arm */ if (n == 0) {
        length = 2;
    } else {
        length = 3;
    }
    consume(length);
}
"""

    _assert_cfg_and_fallback_lines(code, set())


def test_line_comment_between_brace_and_else_keeps_join_live():
    code = """void f(int cond) {
    int x;
    if (cond) {
        x = 1;
    }
    // continue chain
    else {
        x = 2;
    }
    consume(x);
}
"""

    _assert_cfg_and_fallback_lines(code, set())


def test_identifier_ending_in_else_is_not_else_if_continuation():
    """`some_else` / `belse` before `if` must not be treated as `else if`."""
    code = """void f(int cond) {
    int x;
    int some_else = 0;
    if (cond) {
        x = 1;
    } else {
        x = 2;
    }
    consume(x);
    consume(some_else);
}
"""

    _assert_cfg_and_fallback_lines(code, set())


def test_else_prefixed_identifier_is_not_else_keyword():
    """`else_val` after an if body must not be parsed as an `else` arm."""
    code = """void f(int cond) {
    int x;
    int else_val;
    if (cond) {
        x = 1;
    }
    else_val = 2;
    consume(x);
    consume(else_val);
}
"""

    # Without a trailing word boundary, else_val is misread as else and the
    # then-arm store can be reported dead despite the post-join read.
    _assert_cfg_and_fallback_lines(code, set())


def test_if_prefixed_identifier_after_else_is_else_body_not_else_if():
    """`if_var` after `else` must be the else body, not an `else if` header."""
    code = """void f(int cond) {
    int x;
    int if_var;
    if (cond) {
        x = 1;
    } else
        if_var = 2;
    consume(x);
    consume(if_var);
}
"""

    _assert_cfg_and_fallback_lines(code, set())


def test_parse_helpers_respect_keyword_boundaries_and_comments():
    from cgull.rules.dead_stores import (
        _at_keyword,
        _collect_if_else_chains,
        _preceded_by_else,
        _skip_space,
    )

    src = "int x; } /* join */ else { x = 2; }"
    pos = src.index("}") + 1
    assert src[_skip_space(src, pos):].startswith("else")

    src = "else /* next */ if (cond)"
    pos = src.index("else") + 4
    assert src[_skip_space(src, pos):].startswith("if")

    assert _at_keyword("else {", 0, "else")
    assert not _at_keyword("else_val = 1;", 0, "else")
    assert _at_keyword("if (x)", 0, "if")
    assert not _at_keyword("if_var = 1;", 0, "if")

    assert _preceded_by_else("else if", 5)
    assert _preceded_by_else("else /* c */ if", 13)
    assert not _preceded_by_else("some_else if", 10)
    assert not _preceded_by_else("belse if", 6)

    # Full chain still has two arms when a comment sits between } and else.
    code = """void f(int cond) {
    int x;
    if (cond) {
        x = 1;
    } /* exclusive */ else {
        x = 2;
    }
    consume(x);
}
"""
    chains = _collect_if_else_chains(code)
    assert len(chains) == 1
    assert len(chains[0][2]) == 2

def test_same_line_condition_assignment_is_must_overwrite():
    """Condition side effects on a compact `if (...) { ... }` line must kill.

    If the braced body shares the header line, arm spans must not classify the
    condition assignment as an exclusive-arm / may-overwrite store (#530 vs #554).
    """
    code = """void f(void) {
    int x;
    x = 0;
    if (x = 1) { x = 2; } else { x = 3; }
    consume(x);
}
"""
    # Fallback is line-granular: x=0 is dead; the compacted line-4 writes are
    # not split, so only the prior store is required here. CFG may also report
    # the condition assignment as dead once arms overwrite it.
    fallback_issues = scan_dead_stores_fallback(code)
    assert 3 in issue_lines(fallback_issues)
    cfg_issues = scan_with_rule("CGULL-042", code)
    assert 3 in issue_lines(cfg_issues)


def test_same_line_if_without_else_body_still_may_overwrite():
    """Same-line braced body without a condition assign remains a may-overwrite."""
    code = """void f(int c) {
    int x;
    x = 0;
    if (c) { x = 1; }
    consume(x);
}
"""
    _assert_cfg_and_fallback_lines(code, set())


def test_braced_arm_span_excludes_header_when_body_shares_line():
    from cgull.rules.dead_stores import _collect_if_else_chains

    code = """void f(void) {
    int x;
    x = 0;
    if (x = 1) { x = 2; } else { x = 3; }
    consume(x);
}
"""
    chains = _collect_if_else_chains(code)
    assert len(chains) == 1
    header_line, _end, arms, inline_lines, cond_ranges = chains[0]
    assert header_line == 4
    assert inline_lines == frozenset({4})
    # Header line omitted from arm spans (start > end empty spans after bump).
    assert all(start > end or start > header_line for start, end in arms)
    assert len(cond_ranges) == 1
    assert cond_ranges[0][1] > cond_ranges[0][0]



def test_loop_final_write_after_in_body_read_is_still_dead():
    """Last loop write is dead when only earlier in-body reads consume prior stores.

    ``while (cond) { x = 1; consume(x); x = 2; }`` must still report ``x = 2``;
    an earlier body read must not protect the final write across the back-edge.
    """
    code = """void f(int cond) {
    int x = 0;
    while (cond) {
        x = 1;
        consume(x);
        x = 2;
    }
}
"""
    _assert_cfg_and_fallback_lines(code, {6})


def test_loop_body_read_before_first_write_keeps_carried_store_live():
    """A body read before the first overwrite is a true loop-carried use."""
    code = """void f(int cond) {
    int x = 0;
    while (cond) {
        consume(x);
        x = 2;
    }
}
"""
    _assert_cfg_and_fallback_lines(code, set())


def test_comment_text_cannot_fabricate_if_else_chain():
    """Keywords/braces inside comments must not create exclusive-arm spans."""
    code = """void f(void) {
    int x;
    x = 1;
    /* if (cond) { */
    x = 2;
    /* } */
    consume(x);
}
"""
    from cgull.rules.dead_stores import _collect_if_else_chains

    assert _collect_if_else_chains(code) == []
    # Without comment masking, the fabricated if-without-else would treat x=2 as
    # a may-overwrite and suppress the genuine dead store on x=1.
    _assert_cfg_and_fallback_lines(code, {3})


def test_condition_comment_with_paren_still_parses_exclusive_arms():
    """Delimiters inside comments must not truncate if-condition matching."""
    code = """void f(int cond) {
    int x;
    if (cond /* ) */) {
        x = 1;
    } else {
        x = 2;
    }
    consume(x);
}
"""
    from cgull.rules.dead_stores import _collect_if_else_chains, _matching_delimiter

    src = "if (cond /* ) */) { x = 1; }"
    assert _matching_delimiter(src, src.index("("), "(", ")") == src.rindex(")")

    chains = _collect_if_else_chains(code)
    assert len(chains) == 1
    assert len(chains[0][2]) == 2
    _assert_cfg_and_fallback_lines(code, set())


def test_short_circuit_condition_assignment_is_not_must_overwrite():
    """Assignments under ``&&`` / ``||`` do not kill prior stores on all paths."""
    code = """void f(int cond) {
    int x;
    x = 0;
    if (cond && (x = 1)) {
        use(x);
    } else {
        use(x);
    }
    consume(x);
}
"""
    # Fallback join-aware analysis must keep x=0 live when the RHS assign is
    # skipped. CFG may still differ; this regression targets dead_stores.py.
    fallback_issues = scan_dead_stores_fallback(code)
    assert issue_lines(fallback_issues) == set()


def test_short_circuit_or_condition_assignment_is_not_must_overwrite():
    code = """void f(int cond) {
    int x;
    x = 0;
    if (cond || (x = 1)) {
        use(x);
    }
    consume(x);
}
"""
    fallback_issues = scan_dead_stores_fallback(code)
    assert issue_lines(fallback_issues) == set()


def test_left_of_short_circuit_condition_assignment_is_must_overwrite():
    """Left operand of ``&&`` / ``||`` always runs and may kill a prior store."""
    code = """void f(void) {
    int x;
    x = 0;
    if ((x = 1) && other()) {
        use(x);
    } else {
        use(x);
    }
    consume(x);
}
"""
    fallback_issues = scan_dead_stores_fallback(code)
    assert 3 in issue_lines(fallback_issues)
    cfg_issues = scan_with_rule("CGULL-042", code)
    assert 3 in issue_lines(cfg_issues)


def test_ternary_both_arms_assign_is_must_overwrite():
    from cgull.rules.dead_stores import _expr_must_assign

    assert _expr_must_assign("c ? (x = 1) : (x = 2)", "x")
    assert not _expr_must_assign("c ? (x = 1) : y", "x")
    assert not _expr_must_assign("cond && (x = 1)", "x")
    assert _expr_must_assign("(x = 1) && cond", "x")
