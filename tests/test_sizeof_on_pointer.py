"""
Unit tests for CGULL-029 (SizeofOnPointerRule) lexical scoping and symbol resolution.
"""

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id
from cgull.ast_analyzer import CASTParser


def scan_with_rule(rule_id: str, code: str):
    rule = get_rule_by_id(rule_id)
    scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
    return scanner.scan_text(code, f"{rule_id}.c").issues


def test_sizeof_on_pointer_decayed_array_param_same_name_as_global():
    code = """
    int dest = 100;

    void process(char dest[20]) {
        int sz = sizeof(dest);
        (void)sz;
    }
    """
    issues = scan_with_rule("CGULL-029", code)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-029"
    assert "sizeof() used on pointer type 'dest'" in issues[0].message


def test_sizeof_on_pointer_decayed_array_param_with_local_in_other_block():
    code = """
    void process(char dest[20]) {
        int sz1 = sizeof(dest);
        {
            int dest = 5;
            int sz2 = sizeof(dest);
            (void)sz2;
        }
        int sz3 = sizeof(dest);
        (void)sz1;
        (void)sz3;
    }
    """
    issues = scan_with_rule("CGULL-029", code)
    assert len(issues) == 2
    assert all(i.rule_id == "CGULL-029" for i in issues)
    lines = [i.line_number for i in issues]
    assert 3 in lines
    assert 9 in lines
    assert 6 not in lines


def test_sizeof_on_pointer_nested_shadowing_by_pointer():
    code = """
    void process(char dest[20]) {
        {
            char *dest = "hello";
            int sz = sizeof(dest);
            (void)sz;
        }
    }
    """
    issues = scan_with_rule("CGULL-029", code)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-029"


def test_sizeof_on_pointer_global_pointer_shadowed_by_param():
    code = """
    char *buf;

    void process(int buf) {
        int sz = sizeof(buf);
        (void)sz;
    }
    """
    issues = scan_with_rule("CGULL-029", code)
    assert len(issues) == 0


def test_sizeof_on_pointer_fallback_parser_mode():
    code = """
    int dest = 100;

    void process(char dest[20]) {
        int sz = sizeof(dest);
        (void)sz;
    }
    """
    ast_parser = CASTParser()
    ast_ctx = ast_parser.parse(code)
    ast_ctx.has_pycparser = False
    ast_ctx.pycparser_ast = None

    rule = get_rule_by_id("CGULL-029")
    issues = rule.scan_ast("test.c", ast_ctx)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-029"


def test_sizeof_on_pointer_global_pointer():
    code = """
    char *global_buf;

    void process(void) {
        int sz = sizeof(global_buf);
        (void)sz;
    }
    """
    issues = scan_with_rule("CGULL-029", code)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-029"


def test_sizeof_on_pointer_non_matching_expressions():
    code = """
    void process(char *ptr) {
        int sz1 = sizeof(*ptr);
        int sz2 = sizeof(int);
        (void)sz1;
        (void)sz2;
    }
    """
    issues = scan_with_rule("CGULL-029", code)
    assert len(issues) == 0
