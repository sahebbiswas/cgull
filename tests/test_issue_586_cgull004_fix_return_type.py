"""CGULL-004's suggested guard must match the enclosing function's return type (#586)."""

import pytest

from cgull.engine import CGullScanner
from cgull.fixes import apply_safe_fixes
from cgull.models import AnalysisEngine, FixType
from cgull.rules import get_rule_by_id

TYPEDEFS = "typedef struct S { int x; double d; char *s; } S;\ntypedef int custom_status;\n"


def scan(code):
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-004")],
        engine_mode=AnalysisEngine.AST,
    )
    return scanner.scan_text(TYPEDEFS + code, "issue_586.c").issues


def only_issue(code):
    issues = scan(code)
    assert len(issues) == 1, issues
    return issues[0]


@pytest.mark.parametrize(
    "signature, body, expected",
    [
        ("const char *f(const S *p)", "return p->s;", "if (p == NULL) return NULL;"),
        ("S *f(S *p)", "return p->x ? p : 0;", "if (p == NULL) return NULL;"),
        ("static char * const f(S *p)", "return p->s;", "if (p == NULL) return NULL;"),
        ("void f(S *p)", "p->x = 1;", "if (p == NULL) return;"),
        ("static inline void f(S *p)", "p->x = 1;", "if (p == NULL) return;"),
        ("int f(S *p)", "return p->x;", "if (p == NULL) return -EINVAL;"),
        ("long f(S *p)", "return p->x;", "if (p == NULL) return -EINVAL;"),
        ("long long f(S *p)", "return p->x;", "if (p == NULL) return -EINVAL;"),
        ("signed int f(S *p)", "return p->x;", "if (p == NULL) return -EINVAL;"),
    ],
)
def test_mechanical_return_types_get_a_matching_guard(signature, body, expected):
    issue = only_issue(f"{signature} {{ {body} }}")
    assert issue.suggested_fix_replacement == expected
    assert issue.fix_type == FixType.SUGGESTED_FIX
    assert issue.auto_fix_replacement is None


@pytest.mark.parametrize(
    "signature, body",
    [
        ("double f(const S *p)", "return p->d;"),
        ("float f(const S *p)", "return (float)p->d;"),
        ("unsigned f(const S *p)", "return p->x;"),
        ("unsigned long f(const S *p)", "return p->x;"),
        ("size_t f(const S *p)", "return p->x;"),
        ("_Bool f(const S *p)", "return p->x;"),
        ("custom_status f(const S *p)", "return p->x;"),
        ("S f(const S *p)", "return *p;"),
    ],
)
def test_non_mechanical_return_types_get_no_replacement(signature, body):
    issue = only_issue(f"{signature} {{ {body} }}")
    assert issue.suggested_fix_replacement is None
    assert issue.auto_fix_replacement is None
    assert issue.fix_type == FixType.MANUAL_REVIEW
    assert issue.rule_id == "CGULL-004"


def test_local_null_pointer_dereference_uses_matching_guard():
    issues = scan(
        """
        const char *f(void) {
            char *p = NULL;
            return p[0] ? "a" : "b";
        }
        int g(void) {
            int *q = NULL;
            return *q;
        }
        void h(void) {
            int *r = NULL;
            *r = 1;
        }
        double k(void) {
            double *s = NULL;
            return *s;
        }
        """
    )
    by_function = {i.message.split("'")[1]: i for i in issues}
    assert by_function["p"].suggested_fix_replacement == "if (p == NULL) return NULL;"
    assert by_function["q"].suggested_fix_replacement == "if (q == NULL) return -1;"
    assert by_function["r"].suggested_fix_replacement == "if (r == NULL) return;"
    assert by_function["s"].suggested_fix_replacement is None
    assert by_function["s"].fix_type == FixType.MANUAL_REVIEW


@pytest.mark.parametrize(
    "decl, expected, fix_type",
    [
        ("CJSON_PUBLIC(const char*) f(const S *item)", "if (item == NULL) return NULL;", FixType.SUGGESTED_FIX),
        ("CJSON_PUBLIC(void) f(const S *item)", "if (item == NULL) return;", FixType.SUGGESTED_FIX),
        ("CJSON_PUBLIC(int) f(const S *item)", "if (item == NULL) return -EINVAL;", FixType.SUGGESTED_FIX),
        ("CJSON_PUBLIC(double) f(const S *item)", None, FixType.MANUAL_REVIEW),
    ],
)
def test_export_macro_wrapped_return_types_on_fallback_path(decl, expected, fix_type):
    scanner = CGullScanner(rules=[get_rule_by_id("CGULL-004")], engine_mode=AnalysisEngine.AST)
    result = scanner.scan_text(TYPEDEFS + f"{decl} {{ return item->x; }}", "issue_586_macro.c")
    assert result.get_overall_parser_status() != "pycparser"
    assert len(result.issues) == 1
    assert result.issues[0].suggested_fix_replacement == expected
    assert result.issues[0].fix_type == fix_type


def test_cjson_getter_no_longer_suggests_integer_error_return():
    issue = only_issue(
        """
        const char *cJSON_GetStringValue(const S *item)
        {
            return item->s;
        }
        """
    )
    assert "-EINVAL" not in (issue.suggested_fix_replacement or "")
    assert issue.suggested_fix_replacement == "if (item == NULL) return NULL;"


def test_guarded_function_still_reports_nothing():
    assert scan("const char *f(const S *p) { if (p == NULL) return NULL; return p->s; }") == []


def test_fix_pipeline_never_applies_a_cgull004_guard(tmp_path):
    issues = scan("const char *cJSON_GetStringValue(const S *item) { return item->s; }")
    assert [i.fix_type for i in issues] == [FixType.SUGGESTED_FIX]
    result = apply_safe_fixes(issues, write=False)
    assert result.eligible_issues == 0
