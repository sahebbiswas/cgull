"""CGULL-042 regressions for goto liveness and switch fallthrough (#498)."""

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


def test_goto_read_on_one_reachable_path_keeps_prior_write_live():
    code = """void f(int cond) {
    int data;
    data = 5;
    if (cond) goto skip;
    consume(data);
    return;
skip:
    data = 10;
    consume(data);
}
"""

    _assert_cfg_and_fallback_lines(code, set())


def test_goto_overwrite_on_every_path_reports_prior_write():
    code = """void f(int cond) {
    int data;
    data = 5;
    if (cond) goto skip;
skip:
    data = 10;
    consume(data);
}
"""

    _assert_cfg_and_fallback_lines(code, {3})


def test_switch_fallthrough_reports_only_overwritten_case_write():
    code = """void f(int x) {
    int data;
    switch (x) {
        case 1:
            data = 5;
            /* fallthrough */
        case 2:
            data = 10;
            consume(data);
            break;
        default:
            data = 0;
            consume(data);
    }
}
"""

    _assert_cfg_and_fallback_lines(code, {5})
