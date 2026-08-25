"""
Unit tests for CGULL-042 (DeadStoresRule).
"""

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


def scan_with_rule(rule_id: str, code: str):
    rule = get_rule_by_id(rule_id)
    scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
    return scanner.scan_text(code, f"{rule_id}.c").issues


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
    from cgull.ast_analyzer import CASTParser
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
    ast_parser = CASTParser()
    ast_ctx = ast_parser.parse(code)
    ast_ctx.has_pycparser = False
    ast_ctx.pycparser_ast = None
    rule = get_rule_by_id("CGULL-042")
    issues = rule.scan_ast("test.c", ast_ctx)
    assert len(issues) == 0
