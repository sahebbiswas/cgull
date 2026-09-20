"""Regressions for #552 (CGULL-011) and #556 (CGULL-034)."""

from pathlib import Path

from cgull.ast_analyzer import CASTParser
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id
from cgull.rules.crypto_and_safety import (
    IllegalFunctionPointerConversionsRule,
    _FUNC_PTR_CAST_RE,
    _is_macro_type_declarator_cast,
)


def _scan(rule_id: str, code: str):
    rule = get_rule_by_id(rule_id)
    return CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID).scan_text(
        code, f"{rule_id}.c"
    ).issues


def _force_fallback(code: str):
    ctx = CASTParser().parse(code)
    ctx.has_pycparser = False
    ctx.pycparser_ast = None
    return ctx


def test_export_macro_declarator_not_flagged_in_fallback():
    code = """
EXPORT(int) foo(void);
EXPORT(void *) bar(unsigned long n);
CJSON_PUBLIC(int) cJSON_GetArraySize(const void *array);
CJSON_PUBLIC(void *) cJSON_malloc(unsigned long size);
int foo(void) { return 0; }
void *bar(unsigned long n) { return 0; }
int cJSON_GetArraySize(const void *array) { return 0; }
void *cJSON_malloc(unsigned long size) { return 0; }
"""
    issues = IllegalFunctionPointerConversionsRule().scan_ast("t.c", _force_fallback(code))
    assert issues == []


def test_true_function_pointer_cast_still_flagged_alongside_export_macros():
    code = """
EXPORT(int) foo(void);
int foo(void) { return 0; }
void my_handler(int x) {}
void bad(void) {
    void *p = (void *)my_handler;
    int addr = (int)my_handler;
}
"""
    issues = IllegalFunctionPointerConversionsRule().scan_ast("t.c", _force_fallback(code))
    assert len(issues) == 2
    assert all("my_handler" in i.message for i in issues)
    assert all("foo" not in i.message for i in issues)


def test_macro_type_declarator_helper_accepts_export_shape():
    line = "CJSON_PUBLIC(void *) cJSON_malloc(size_t size)"
    match = _FUNC_PTR_CAST_RE.search(line)
    assert match is not None
    assert _is_macro_type_declarator_cast(line, match)


def test_macro_type_declarator_helper_rejects_real_cast():
    line = "void *p = (void *)my_handler;"
    match = _FUNC_PTR_CAST_RE.search(line)
    assert match is not None
    assert not _is_macro_type_declarator_cast(line, match)


def test_return_keyword_cast_not_treated_as_macro():
    """'return (int)my_handler' must remain a true positive candidate."""
    line = "return (int)my_handler;"
    match = _FUNC_PTR_CAST_RE.search(line)
    assert match is not None
    assert not _is_macro_type_declarator_cast(line, match)


def test_nan_macro_return_not_flagged():
    code = """
#ifndef NAN
#define NAN (0.0/0.0)
#endif
double get_nan(void) {
    return (double) NAN;
}
"""
    assert _scan("CGULL-034", code) == []


def test_direct_nan_literal_division_not_flagged():
    code = """
double get_nan(void) { return 0.0/0.0; }
double get_nanf(void) { return 0.0f/0.0f; }
"""
    assert _scan("CGULL-034", code) == []


def test_runtime_div_by_zero_still_flagged():
    code = """
int vulnerable(int y) { return 100 / y; }
int literal_zero(void) { return 100 / 0; }
double float_inf(void) { return 1.0 / 0.0; }
"""
    issues = _scan("CGULL-034", code)
    assert len(issues) == 3


def test_cjson_windows_fallback_no_longer_emits_cgull_011():
    cjson = Path("/workspace/cgull-work/cjson/cJSON.c")
    if not cjson.is_file():
        return
    ctx = CASTParser().parse(
        cjson.read_text(),
        defined_syms={"_MSC_VER": 1, "_WIN32": 1, "__WINDOWS__": 1},
    )
    assert not ctx.has_pycparser
    issues = IllegalFunctionPointerConversionsRule().scan_ast("cJSON.c", ctx)
    assert issues == []


def test_unparenthesized_nan_macro_with_outer_cast_not_flagged():
    """cJSON-style: `#define NAN 0.0/0.0` then `return (double)NAN`."""
    code = """
#ifndef NAN
#define NAN 0.0/0.0
#endif
double get_nan(void) {
    return (double) NAN;
}
"""
    assert _scan("CGULL-034", code) == []


def test_casted_float_zero_over_float_zero_not_flagged():
    code = """
double get_nan(void) {
    return ((double)0.0) / 0.0;
}
"""
    assert _scan("CGULL-034", code) == []
