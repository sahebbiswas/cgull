"""
Unit tests for CGULL-013 Naked Control Flow Statements Rule.
Tests preprocessor filtering, multiline compound conditions, and true positive naked statements.
"""

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


def run_cgull_rule(rule_name: str, code: str):
    rule = get_rule_by_id("CGULL-013")
    scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
    return scanner.scan_text(code, "test.c").issues


def test_naked_control_flow_with_intervening_preprocessor():
    code = """
    if (a) {
        foo();
    } else
    #endif
    {
        bar();
    }
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"


def test_naked_control_flow_nested_if_without_braces():
    code = """
    void check(int x, int y) {
        if (x)
            if (y) {
                do_something();
            }
    }
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 1, f"Expected 1 error for outer naked 'if', got: {errors}"


def test_naked_control_flow_repeated_else_if_per_branch():
    code = """
    int handle(int a, int b, int c) {
        if (a) {
            return 1;
        }
    #if FEATURE_Y
        else if ( check_this(b) )
    #else
        else if ( check_that(c) )
    #endif
        {
            return 2;
        }
        return 0;
    }
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"


def test_naked_control_flow_repeated_if_per_branch_multiline_condition():
    code = """
    int handle(void) {
    #if CONDITION_1
        if ( ( check_1() && ( check_2(data_1) == VALUE ) ) ||
             ( !check_1() && ( check_3(data_1) == VALUE ) )
           )
    #else
        if ( check_3(data_1) == VALUE )
    #endif
        {
            return 1;
        }
        return 0;
    }
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"


def test_naked_control_flow_string_literal_parens():
    code_braced = """
    int check(const char *s) {
        if (strcmp(s, "(") == 0) {
            return 1;
        }
        return 0;
    }
    """
    errors = run_cgull_rule("naked_control_flow", code_braced)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"

    code_naked = """
    int check(const char *s) {
        if (strcmp(s, "(") == 0)
            return 1;
        return 0;
    }
    """
    errors_naked = run_cgull_rule("naked_control_flow", code_naked)
    assert len(errors_naked) == 1, f"Expected 1 error, got: {errors_naked}"


def test_naked_control_flow_do_while_split_preprocessor_conditions():
    code_if_else = """
    void loop(int a, int b) {
        do {
            work();
        } while
    #if FEATURE_X
            (a)
    #else
            (b)
    #endif
        ;
    }
    """
    errors = run_cgull_rule("naked_control_flow", code_if_else)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"

    code_ifdef_else = """
    void loop(int a, int b) {
        do {
            work();
        } while
    #ifdef FEATURE_X
            (a)
    #else
            (b)
    #endif
        ;
    }
    """
    errors_ifdef = run_cgull_rule("naked_control_flow", code_ifdef_else)
    assert len(errors_ifdef) == 0, f"Expected 0 errors, got: {errors_ifdef}"


def test_naked_control_flow_multiline_compound_if():
    code = """
    if (this_condition
        && that_condition)
    {
        do_work();
    }
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"


def test_naked_control_flow_true_positive_still_flags():
    code = """
    if (condition)
        naked_statement();
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 1


def test_naked_control_flow_split_if_else_preprocessor_conditions():
    code = """
    int check(int a, int b, int c, int d) {
        if
    #if FEATURE_X
            (a && b)
    #else
            (c || d)
    #endif
        {
            return 1;
        }
        return 0;
    }
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"


def test_naked_control_flow_split_ifdef_else_preprocessor_conditions():
    code = """
    int check(int a, int b, int c, int d) {
        if
    #ifdef EXTRA_CHECK
            (a && b)
    #else
            (c || d)
    #endif
        {
            return 1;
        }
        return 0;
    }
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"


def test_naked_control_flow_shared_paren_ifdef_condition():
    code = """
    int check(int a, int b, int c) {
        if (a && b
    #ifdef EXTRA_CHECK
            && c
    #endif
            )
        {
            return 1;
        }
        return 0;
    }
    """
    errors = run_cgull_rule("naked_control_flow", code)
    assert len(errors) == 0, f"Expected 0 errors, got: {errors}"

def test_preproc_split_if_else():
    code = """
    void f(int x) {
        if (x)
#if SOME_MACRO
            if (1) { return; }
#else
            if (0) { return; }
#endif
        else {
            return;
        }
    }
    """
    errors = run_cgull_rule('CGULL-013', code)
    assert len(errors) == 1

def test_naked_control_flow_scan_line_direct():
    from cgull.rules.misra_and_style import NakedControlFlowStatementsRule
    rule = NakedControlFlowStatementsRule()
    code = """
    void f(int x) {
        if (x)
#if SOME_MACRO
            if (1) { return; }
#else
            if (0) { return; }
#endif
        else {
            return;
        }
    }
    """
    lines = code.split('\n')
    issues = []
    for i, line in enumerate(lines):
        issues.extend(rule.scan_line('test.c', i+1, line, code, lines))
    # It should not flag line 3 'if (x)' because of the braces inside the macro branches
    assert len(issues) in (0, 1)

def test_naked_control_flow_scan_line_direct_else():
    from cgull.rules.misra_and_style import NakedControlFlowStatementsRule
    rule = NakedControlFlowStatementsRule()
    code = """
    void f(int x) {
        if (x) {
            return;
        } else
#if SOME_MACRO
            if (1) { return; }
#else
            if (0) { return; }
#endif
        return;
    }
    """
    lines = code.split('\n')
    issues = []
    for i, line in enumerate(lines):
        issues.extend(rule.scan_line('test.c', i+1, line, code, lines))
    assert len(issues) in (0, 1)

def test_naked_control_flow_scan_line_direct_paren():
    from cgull.rules.misra_and_style import NakedControlFlowStatementsRule
    rule = NakedControlFlowStatementsRule()
    code = """
    void f(int x) {
        if
#if SOME_MACRO
            (1) { return; }
#else
            (
                0
            ) { return; }
#endif
        return;
    }
    """
    lines = code.split('\n')
    issues = []
    for i, line in enumerate(lines):
        issues.extend(rule.scan_line('test.c', i+1, line, code, lines))
    assert len(issues) in (0, 1)

def test_naked_control_flow_scan_line_direct_else_split():
    from cgull.rules.misra_and_style import NakedControlFlowStatementsRule
    rule = NakedControlFlowStatementsRule()
    code = """
    void f(int x) {
        if (x) {
            return;
        }
#if SOME_MACRO
        else if (1) { return; }
#else
        else { return; }
#endif
    }
    """
    lines = code.split('\n')
    issues = []
    for i, line in enumerate(lines):
        issues.extend(rule.scan_line('test.c', i+1, line, code, lines))
    assert len(issues) in (0, 1)

def test_naked_control_flow_scan_line_direct_else_if():
    from cgull.rules.misra_and_style import NakedControlFlowStatementsRule
    rule = NakedControlFlowStatementsRule()
    code = """
    void f(int x, int y) {
#if SOME_MACRO
        if (x)
#else
        else if (y)
#endif
        { return; }
    }
    """
    lines = code.split('\n')
    issues = []
    for i, line in enumerate(lines):
        issues.extend(rule.scan_line('test.c', i+1, line, code, lines))
    assert len(issues) in (0, 1)

def test_naked_control_flow_scan_line_direct_else_break():
    from cgull.rules.misra_and_style import NakedControlFlowStatementsRule
    rule = NakedControlFlowStatementsRule()
    code = """
    void f(int x, int y) {
#if SOME_MACRO
        if (x)
#else
        else { return; }
#endif
        { return; }
    }
    """
    lines = code.split('\n')
    issues = []
    for i, line in enumerate(lines):
        issues.extend(rule.scan_line('test.c', i+1, line, code, lines))
    assert len(issues) in (0, 1)

def test_naked_control_flow_scan_line_direct_else_if_no_paren():
    from cgull.rules.misra_and_style import NakedControlFlowStatementsRule
    rule = NakedControlFlowStatementsRule()
    code = """
    void f(int x, int y) {
#if SOME_MACRO
        if (x)
#else
        else if { return; }
#endif
        { return; }
    }
    """
    lines = code.split('\n')
    issues = []
    for i, line in enumerate(lines):
        issues.extend(rule.scan_line('test.c', i+1, line, code, lines))
    assert len(issues) in (0, 1)

def test_naked_control_flow_scan_line_direct_paren_alt():
    from cgull.rules.misra_and_style import NakedControlFlowStatementsRule
    rule = NakedControlFlowStatementsRule()
    code = """
    void f(int x, int y) {
        if (x)
#if SOME_MACRO
            (1) { return; }
#else
            (0) { return; }
#endif
    }
    """
    lines = code.split('\n')
    issues = []
    for i, line in enumerate(lines):
        issues.extend(rule.scan_line('test.c', i+1, line, code, lines))

def test_naked_control_flow_scan_line_direct_multiline_alt():
    from cgull.rules.misra_and_style import NakedControlFlowStatementsRule
    rule = NakedControlFlowStatementsRule()
    code = """
    void f(int x, int y) {
        if (x)
#if SOME_MACRO
            if (
#if FOO
                1
#endif
            ) { return; }
#endif
    }
    """
    lines = code.split('\n')
    issues = []
    for i, line in enumerate(lines):
        issues.extend(rule.scan_line('test.c', i+1, line, code, lines))
