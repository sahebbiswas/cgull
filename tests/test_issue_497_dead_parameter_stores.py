"""Regression tests for issue #497: CGULL-042 parameter dead stores."""

from unittest.mock import patch

from cgull.ast_analyzer import CASTParser
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


def scan_dead_stores(code: str):
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-042")],
        engine_mode=AnalysisEngine.HYBRID,
    )
    return scanner.scan_text(code, "issue_497.c").issues


def scan_dead_stores_fallback(code: str):
    ast_ctx = CASTParser().parse(code)
    ast_ctx.has_pycparser = False
    ast_ctx.pycparser_ast = None
    return get_rule_by_id("CGULL-042").scan_ast("issue_497.c", ast_ctx)


def scan_dead_stores_lexical(code: str):
    with patch.object(CASTParser, "_try_pycparser", return_value=(None, False)):
        ast_ctx = CASTParser().parse(code)
    assert not ast_ctx.has_pycparser
    return get_rule_by_id("CGULL-042").scan_ast("issue_497.c", ast_ctx)


def issue_lines(issues):
    return {issue.line_number for issue in issues if issue.rule_id == "CGULL-042"}


def test_terminal_parameter_assignment_is_dead_in_full_and_fallback_modes():
    code = """void f(int x) {
    x = 1;
}
"""
    for scan in (scan_dead_stores, scan_dead_stores_fallback, scan_dead_stores_lexical):
        assert 2 in issue_lines(scan(code))


def test_only_first_overwritten_parameter_assignment_is_dead():
    code = """int first(void);
int second(void);
void consume(int value);
void f(int x) {
    x = first();
    x = second();
    consume(x);
}
"""
    for scan in (scan_dead_stores, scan_dead_stores_fallback, scan_dead_stores_lexical):
        lines = issue_lines(scan(code))
        assert 5 in lines
        assert 6 not in lines


def test_incoming_parameter_value_and_written_then_read_value_are_not_dead():
    incoming_only = """void consume(int value);
void f(int x) {
    consume(x);
}
"""
    written_then_read = """void consume(int value);
void f(int x) {
    x = 1;
    consume(x);
}
"""
    for scan in (scan_dead_stores, scan_dead_stores_fallback, scan_dead_stores_lexical):
        assert not issue_lines(scan(incoming_only))
        assert not issue_lines(scan(written_then_read))


def test_parameter_write_consumed_on_loop_backedge_is_not_dead():
    code = """int next_value(void);
void f(int x) {
    while (x > 0) {
        x = next_value();
    }
}
"""
    for scan in (scan_dead_stores, scan_dead_stores_fallback, scan_dead_stores_lexical):
        assert 4 not in issue_lines(scan(code))


def test_shadowed_local_read_does_not_keep_parameter_write_live():
    code = """void consume(int value);
void f(int x) {
    x = 1;
    {
        int x;
        x = 2;
        consume(x);
    }
}
"""
    for scan in (scan_dead_stores, scan_dead_stores_fallback, scan_dead_stores_lexical):
        lines = issue_lines(scan(code))
        assert 3 in lines
        assert 6 not in lines


def test_volatile_and_address_taken_parameters_remain_conservative():
    code = """void f(volatile int x) {
    x = 1;
}
void g(int y) {
    int *p = &y;
    y = 2;
    (void)p;
}
"""
    for scan in (scan_dead_stores, scan_dead_stores_fallback, scan_dead_stores_lexical):
        assert not issue_lines(scan(code))


def test_cgull_020_unused_argument_behavior_is_unchanged():
    code = """void used(int x) {
    x = 1;
}
void unused(int y) {
}
"""
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-020")],
        engine_mode=AnalysisEngine.HYBRID,
    )
    issues = scanner.scan_text(code, "issue_497_unused.c").issues
    assert len(issues) == 1
    assert "'y'" in issues[0].message


def test_parameter_scope_resumes_after_sibling_blocks():
    code = """void consume(int value);
void f(int x) {
    {
        int x;
        x = 2;
        consume(x);
    }
    x = 3;
    {
        int x;
        x = 4;
        consume(x);
    }
    x = 5;
    consume(x);
}
"""
    for scan in (scan_dead_stores, scan_dead_stores_fallback, scan_dead_stores_lexical):
        assert issue_lines(scan(code)) == {8}
