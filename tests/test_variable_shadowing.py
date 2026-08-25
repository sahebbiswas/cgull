"""
Unit tests for CGULL-043 (VariableShadowingRule).
"""

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine, Severity, RuleCategory
from cgull.rules import get_rule_by_id


def scan_with_rule(rule_id: str, code: str):
    rule = get_rule_by_id(rule_id)
    scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
    return scanner.scan_text(code, f"{rule_id}.c").issues


def test_variable_shadowing_parameter_shadows_global():
    code = """
    int global_var = 100;

    void process(int global_var) {
        (void)global_var;
    }
    """
    issues = scan_with_rule("CGULL-043", code)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-043"
    assert "Parameter 'global_var'" in issues[0].message


def test_variable_shadowing_local_shadows_parameter():
    code = """
    void calculate(int total) {
        int total = 0;
        (void)total;
    }
    """
    issues = scan_with_rule("CGULL-043", code)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-043"
    assert "shadows function parameter 'total'" in issues[0].message


def test_variable_shadowing_local_shadows_global():
    code = """
    int max_retries = 3;

    void run(void) {
        int max_retries = 5;
        (void)max_retries;
    }
    """
    issues = scan_with_rule("CGULL-043", code)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-043"
    assert "shadows global variable 'max_retries'" in issues[0].message


def test_variable_shadowing_nested_block():
    code = """
    void foo(void) {
        int x = 1;
        if (x > 0) {
            int x = 2;
            (void)x;
        }
    }
    """
    issues = scan_with_rule("CGULL-043", code)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-043"
    assert "shadows variable 'x' declared in an outer scope" in issues[0].message


def test_variable_shadowing_for_loop():
    code = """
    void foo(void) {
        int i = 0;
        for (int i = 0; i < 10; i++) {
            (void)i;
        }
    }
    """
    issues = scan_with_rule("CGULL-043", code)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-043"
    assert "shadows variable 'i' declared in an outer scope" in issues[0].message


def test_variable_shadowing_sibling_blocks_no_false_positive():
    code = """
    void foo(int cond) {
        if (cond) {
            int val = 1;
            (void)val;
        } else {
            int val = 2;
            (void)val;
        }
    }
    """
    issues = scan_with_rule("CGULL-043", code)
    assert len(issues) == 0


def test_variable_shadowing_clean_code():
    code = """
    int g_val = 100;

    void foo(int param_a) {
        int local_b = param_a + g_val;
        if (local_b > 0) {
            int inner_c = local_b * 2;
            (void)inner_c;
        }
    }
    """
    issues = scan_with_rule("CGULL-043", code)
    assert len(issues) == 0


def test_variable_shadowing_rule_definition():
    rule = get_rule_by_id("CGULL-043")
    defn = rule.get_definition()
    assert defn.rule_id == "CGULL-043"
    assert defn.impact == Severity.LOW
    assert defn.category == RuleCategory.STYLE
    assert defn.cwe_id == "CWE-398 / MISRA C:2012 Rule 5.3"
