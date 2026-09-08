"""
Unit tests for CGULL-042 (DeadStoresRule).
"""

from cgull.ast_analyzer import CASTParser
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


def scan_with_rule(rule_id: str, code: str):
    rule = get_rule_by_id(rule_id)
    scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
    return scanner.scan_text(code, f"{rule_id}.c").issues


def scan_dead_stores_fallback(code: str):
    ast_ctx = CASTParser().parse(code)
    ast_ctx.has_pycparser = False
    ast_ctx.pycparser_ast = None
    return get_rule_by_id("CGULL-042").scan_ast("test.c", ast_ctx)


def issue_lines(issues):
    return {issue.line_number for issue in issues if issue.rule_id == "CGULL-042"}


def test_dead_stores_basic():
    code = """
    int compute(void) { return 42; }

    void foo(void) {
        int status = compute();
        status = 0;
    }
    """
    issues = scan_with_rule("CGULL-042", code)
    assert len(issues) >= 1
    rule_ids = [i.rule_id for i in issues]
    assert "CGULL-042" in rule_ids


def test_dead_stores_volatile_and_address_taken():
    code = """
    void foo(void) {
        volatile int v = 1;
        v = 2;

        int a = 10;
        int *p = &a;
        a = 20;
        (void)p;
    }
    """
    issues = scan_with_rule("CGULL-042", code)
    assert len(issues) == 0


def test_dead_stores_fallback_mode_address_taken_and_reads():
    code = """
    void foo(void) {
        volatile int v = 1;
        v = 2;

        int a = 10;
        int *p = &a;
        a = 20;
        (void)p;

        int used = 5;
        use_val(used);
    }
    """
    issues = scan_dead_stores_fallback(code)
    assert len(issues) == 0


def test_dead_stores_cfg_while_loop_carried_call_argument_is_not_dead():
    code = """int someapi(int x) { return x > 0; }
int get_new_value(void) { return 1; }
void f(void) {
    int X = 3;
    while (someapi(X)) {
        X = get_new_value();
    }
}
"""
    issues = scan_with_rule("CGULL-042", code)
    assert 6 not in issue_lines(issues)


def test_dead_stores_fallback_while_loop_carried_call_argument_is_not_dead():
    code = """int someapi(int x) { return x > 0; }
int get_new_value(void) { return 1; }
void f(void) {
    int X = 3;
    while (someapi(X)) {
        X = get_new_value();
    }
}
"""
    issues = scan_dead_stores_fallback(code)
    assert 6 not in issue_lines(issues)


def test_dead_stores_fallback_issue_example_with_rhs_read_is_not_dead():
    code = """int someapi(int x) { return x > 0; }
int get_new_value(int x) { return x - 1; }
void f(void) {
    int X = 3;
    while (someapi(X)) {
        X = get_new_value(X);
    }
}
"""
    issues = scan_dead_stores_fallback(code)
    assert 6 not in issue_lines(issues)


def test_dead_stores_fallback_direct_while_condition_read_is_not_dead():
    code = """int get_new_value(void) { return 1; }
void f(void) {
    int X = 3;
    while (X > 0) {
        X = get_new_value();
    }
}
"""
    issues = scan_dead_stores_fallback(code)
    assert 5 not in issue_lines(issues)


def test_dead_stores_fallback_do_while_condition_read_is_not_dead():
    code = """int someapi(int x) { return x > 0; }
int get_new_value(void) { return 1; }
void f(void) {
    int X = 3;
    do {
        X = get_new_value();
    } while (someapi(X));
}
"""
    issues = scan_dead_stores_fallback(code)
    assert 6 not in issue_lines(issues)


def test_dead_stores_fallback_for_condition_read_is_not_dead():
    code = """int someapi(int x) { return x > 0; }
int get_new_value(void) { return 1; }
void f(void) {
    int X = 3;
    for (; someapi(X); ) {
        X = get_new_value();
    }
}
"""
    issues = scan_dead_stores_fallback(code)
    assert 6 not in issue_lines(issues)


def test_dead_stores_fallback_for_iteration_read_is_not_dead():
    code = """int get_new_value(void) { return 1; }
void f(void) {
    int X = 0;
    for (int i = 0; i < 3; consume(X), ++i) {
        X = get_new_value();
    }
}
"""
    issues = scan_dead_stores_fallback(code)
    assert 5 not in issue_lines(issues)


def test_dead_stores_fallback_loop_without_read_still_reports():
    code = """int keep_running(void) { return 1; }
int get_new_value(void) { return 1; }
void f(void) {
    int X = 0;
    while (keep_running()) {
        X = get_new_value();
    }
}
"""
    issues = scan_dead_stores_fallback(code)
    assert 6 in issue_lines(issues)


def test_dead_stores_fallback_does_not_blanket_suppress_loop_writes():
    code = """void f(void) {
    int X = 1;
    while (X > 0) {
        X = 1;
        X = 2;
    }
}
"""
    issues = scan_dead_stores_fallback(code)
    lines = issue_lines(issues)
    assert 4 in lines
    assert 5 not in lines
