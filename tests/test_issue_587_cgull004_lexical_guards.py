"""CGULL-004 must honor guards in its regex-fallback path too (#587).

An undefined export macro such as ``CJSON_PUBLIC(type)`` sends a file through
the fallback parser, where parameter uses are judged from source text.  That
path must honor the same guards the CFG path honors: enclosing loop/if
conditions, dominating early exits, short circuits, and same-file ``Is*``
predicates, while still reporting genuinely unguarded uses.
"""

import pytest

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id
from cgull.rules.memory_management.lexical_null_guards import (
    LexicalBody,
    cond_false_proves_nonnull,
    cond_true_proves_nonnull,
    derive_truthy_nonnull_predicates,
    is_falsy_return,
)

PRELUDE = """
typedef int cJSON_bool;
#define false ((cJSON_bool)0)
typedef struct cJSON { struct cJSON *next; struct cJSON *child; char *valuestring; double valuedouble; int type; } cJSON;
"""

# Leaves the export macro undefined so the file takes the fallback parser tier.
FALLBACK_MACROS = "CJSON_PUBLIC"
# Defines it so the same code is parsed by pycparser and analyzed on the CFG path.
AST_DEFINES = "#define CJSON_PUBLIC(type) type\n"


def scan(code, *, fallback=True):
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-004")],
        engine_mode=AnalysisEngine.AST,
    )
    prefix = "" if fallback else AST_DEFINES
    result = scanner.scan_text(prefix + PRELUDE + code, "issue_587.c")
    parser = result.get_overall_parser_status()
    if fallback:
        assert parser != "pycparser", "fixture was expected to take the fallback parser tier"
    else:
        assert parser == "pycparser", "fixture was expected to be parsed by pycparser"
    return result.issues


MODES = pytest.mark.parametrize("fallback", [True, False], ids=["fallback-parser", "pycparser"])

PREDICATES = """
CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)
{
    if (item == NULL)
    {
        return false;
    }
    return (item->type & 0xFF) == 16;
}

CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)
{
    if (item == NULL)
    {
        return false;
    }
    return (item->type & 0xFF) == 8;
}
"""


@MODES
def test_is_predicate_guard_defined_after_use(fallback):
    code = f"""
    CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item);
    CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item);

    CJSON_PUBLIC(const char*) cJSON_GetStringValue(const cJSON * const item)
    {{
        if (!cJSON_IsString(item))
        {{
            return NULL;
        }}

        return item->valuestring;
    }}

    CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)
    {{
        if (!cJSON_IsNumber(item))
        {{
            return (double)0.0;
        }}

        return item->valuedouble;
    }}
    {PREDICATES}
    """
    assert scan(code, fallback=fallback) == []


@MODES
def test_is_predicate_guard_defined_before_use(fallback):
    code = f"""
    {PREDICATES}
    CJSON_PUBLIC(const char*) get(const cJSON * const item)
    {{
        if (!cJSON_IsString(item)) return NULL;
        return item->valuestring;
    }}
    """
    assert scan(code, fallback=fallback) == []


@MODES
def test_positive_predicate_branch_guards_body(fallback):
    code = f"""
    {PREDICATES}
    CJSON_PUBLIC(double) get(const cJSON * const item)
    {{
        double out = 0.0;
        if (cJSON_IsNumber(item))
        {{
            out = item->valuedouble;
        }}
        return out;
    }}
    """
    assert scan(code, fallback=fallback) == []


def test_predicate_that_does_not_check_null_is_not_a_guard():
    code = """
    CJSON_PUBLIC(cJSON_bool) looks_like_string(const cJSON * const item)
    {
        return (item->type & 0xFF) == 16;
    }

    CJSON_PUBLIC(const char*) get(const cJSON * const item)
    {
        if (!looks_like_string(item))
        {
            return NULL;
        }
        return item->valuestring;
    }
    """
    messages = [issue.message for issue in scan(code)]
    assert any("'item' in function 'get'" in m for m in messages)


@MODES
def test_while_not_null_guards_loop_body(fallback):
    code = """
    CJSON_PUBLIC(void) cJSON_Delete(cJSON *item)
    {
        cJSON *next = NULL;
        while (item != NULL)
        {
            next = item->next;
            if (item->child != NULL)
            {
                cJSON_Delete(item->child);
            }
            item = next;
        }
    }
    """
    assert scan(code, fallback=fallback) == []


@pytest.mark.parametrize(
    "header",
    [
        "while (p)",
        "while (NULL != p)",
        "for (; p != NULL; p = p->next)",
        "for (cJSON *q = p; q; q = q->next)",
    ],
)
def test_loop_conditions_guard_the_loop_variable(header):
    var = "q" if "q" in header else "p"
    code = f"""
    CJSON_PUBLIC(int) count(cJSON *p)
    {{
        int n = 0;
        {header}
        {{
            n += {var}->type;
        }}
        return n;
    }}
    """
    assert scan(code) == []


def test_loop_guard_does_not_cover_use_after_the_loop():
    code = """
    CJSON_PUBLIC(int) last(cJSON *p)
    {
        int n = 0;
        while (p != NULL)
        {
            n += 1;
        }
        return p->type + n;
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "'p' in function 'last'" in issues[0].message


@MODES
def test_unguarded_setter_still_reports(fallback):
    code = """
    CJSON_PUBLIC(void) set(cJSON *p)
    {
        p->type = 1;
    }
    """
    issues = scan(code, fallback=fallback)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-004"


FILLER = "    int a = 1;\n    int b = 2;\n    int c = 3;\n    int d = 4;\n    int e = 5;\n    int f = 6;\n    int g = 7;\n"


def test_early_exit_guard_after_the_first_lines_dominates_later_use():
    code = f"""
    CJSON_PUBLIC(int) get(cJSON *p)
    {{
    {FILLER}
        if (p == NULL)
        {{
            return -1;
        }}
        return p->type + a;
    }}
    """
    assert scan(code) == []


def test_non_exiting_null_branch_is_not_a_guard():
    code = f"""
    CJSON_PUBLIC(int) get(cJSON *p)
    {{
    {FILLER}
        if (p == NULL)
        {{
            a = 0;
        }}
        return p->type + a;
    }}
    """
    assert len(scan(code)) == 1


def test_guard_in_a_closed_inner_block_does_not_dominate():
    code = f"""
    CJSON_PUBLIC(int) get(cJSON *p, int flag)
    {{
    {FILLER}
        if (flag)
        {{
            if (!p) return -1;
        }}
        return p->type + a;
    }}
    """
    assert len(scan(code)) == 1


def test_else_branch_of_null_test_is_guarded():
    code = f"""
    CJSON_PUBLIC(int) get(cJSON *p)
    {{
    {FILLER}
        if (p == NULL)
        {{
            a = 0;
        }}
        else
        {{
            a = p->type;
        }}
        return a;
    }}
    """
    assert scan(code) == []


@pytest.mark.parametrize(
    "expression",
    [
        "p != NULL && p->type",
        "p && p->type",
        "!p || p->type",
        "p == NULL || p->type",
        "p ? p->type : 0",
        "cJSON_IsString(p) && p->type",
        "!cJSON_IsString(p) || p->type",
    ],
)
def test_same_statement_short_circuits_guard_the_use(expression):
    code = f"""
    {PREDICATES}
    CJSON_PUBLIC(int) get(cJSON *p)
    {{
    {FILLER}
        return {expression};
    }}
    """
    assert scan(code) == []


def test_short_circuit_on_another_pointer_does_not_guard():
    code = f"""
    CJSON_PUBLIC(int) get(cJSON *p, cJSON *q)
    {{
    {FILLER}
        return q != NULL && p->type;
    }}
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "'p' in function 'get'" in issues[0].message


def test_first_unguarded_use_is_reported_after_a_guarded_one():
    code = f"""
    CJSON_PUBLIC(int) get(cJSON *p)
    {{
    {FILLER}
        int n = 0;
        while (p != NULL)
        {{
            n += p->type;
            break;
        }}
        n += p->type;
        return n;
    }}
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "n += p->type;" in issues[0].code_snippet
    assert issues[0].line_number > 0


def test_braceless_same_line_guard_does_not_make_next_line_null():
    code = """
    CJSON_PUBLIC(int) get(cJSON *p)
    {
        if (!p) return -1;
        return p->type;
    }
    """
    assert scan(code) == []


def test_braceless_guard_on_local_pointer_does_not_make_next_line_null():
    code = """
    CJSON_PUBLIC(int) get(cJSON *list)
    {
        cJSON *p = list;
        if (p == NULL) return -1;
        return p->type;
    }
    """
    assert scan(code) == []


def test_string_literal_braces_do_not_confuse_guard_regions():
    code = f"""
    CJSON_PUBLIC(int) get(cJSON *p)
    {{
    {FILLER}
        const char *s = "if (p) {{";
        if (!p) return -1;
        return p->type + a;
    }}
    """
    assert scan(code) == []


# -- lexical helper unit tests ------------------------------------------------


def test_condition_proof_helpers():
    preds = {"IsFoo": frozenset({0})}
    assert cond_true_proves_nonnull("p", "p", preds)
    assert cond_true_proves_nonnull("(a && p != NULL)", "p", preds)
    assert cond_true_proves_nonnull("IsFoo(p)", "p", preds)
    assert not cond_true_proves_nonnull("IsFoo(q)", "p", preds)
    assert not cond_true_proves_nonnull("p || q", "p", preds)
    assert not cond_true_proves_nonnull("!p", "p", preds)
    assert cond_false_proves_nonnull("!p", "p", preds)
    assert cond_false_proves_nonnull("p == NULL || x", "p", preds)
    assert cond_false_proves_nonnull("!IsFoo(p)", "p", preds)
    assert not cond_false_proves_nonnull("!p && x", "p", preds)
    assert not cond_false_proves_nonnull("p != NULL", "p", preds)


def test_falsy_return_normalization():
    for expr in ("", "0", "NULL", "false", "((cJSON_bool)0)", "(double)0.0", "(void *)0"):
        assert is_falsy_return(expr), expr
    for expr in ("1", "(item->type & 0xFF) == 16", "item->valuestring", "ok"):
        assert not is_falsy_return(expr), expr


class _Param:
    def __init__(self, name, is_pointer=True):
        self.name = name
        self.is_pointer = is_pointer


class _Fn:
    def __init__(self, name, params, body):
        self.name = name
        self.parameters = params
        self.body = body


def test_predicate_derivation_requires_every_truthy_return_to_be_guarded():
    guarded = _Fn("IsOk", [_Param("p")], "{\n if (p == NULL) {\n return false;\n }\n return p->type == 1;\n}")
    early_truthy = _Fn("Early", [_Param("p")], "{\n if (flag) {\n return 1;\n }\n if (p == NULL) {\n return 0;\n }\n return 2;\n}")
    no_guard = _Fn("NoGuard", [_Param("p")], "{\n return p->type == 1;\n}")
    truthy_guard_return = _Fn("Bad", [_Param("p")], "{\n if (p == NULL) {\n return 1;\n }\n return 2;\n}")
    predicates = derive_truthy_nonnull_predicates([guarded, early_truthy, no_guard, truthy_guard_return])
    assert predicates == {"IsOk": frozenset({0})}


def test_predicate_arg_index_follows_parameter_position():
    fn = _Fn(
        "IsSecond",
        [_Param("flags", is_pointer=False), _Param("p")],
        "{\n if (!p) {\n return 0;\n }\n return p->type;\n}",
    )
    assert derive_truthy_nonnull_predicates([fn]) == {"IsSecond": frozenset({1})}


def test_lexical_body_guard_queries():
    lines = ["{", "  if (!p) return 0;", "  return p->x;", "}"]
    body = LexicalBody(lines)
    use = body.position(2, lines[2].index("p->x"))
    assert body.is_guarded("p", use, {})
    assert not body.is_guarded("q", use, {})
