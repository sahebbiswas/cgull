"""CGULL-004 must honor short-circuit and callee Is*-style null checks (#551)."""

import pytest

from cgull.ast_analyzer import CASTParser
from cgull.cfg import Nullness, analyze_function_summaries
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


def scan(code):
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-004")],
        engine_mode=AnalysisEngine.AST,
    )
    return scanner.scan_text(code, "issue_551.c").issues


STRUCT = "typedef struct { int type; char *valuestring; double valuedouble; unsigned offset; unsigned length; char *content; } Item;"


@pytest.mark.parametrize(
    "condition",
    [
        "(a == 0) || (b == 0) || ((a->type & 0xFF) != (b->type & 0xFF))",
        "a != 0 && b != 0 && (a->type == b->type)",
        "!(a == 0) && a->type == 1",
    ],
)
def test_short_circuit_null_checks_do_not_fire_on_condition(condition):
    code = f"""
    {STRUCT}
    int f(const Item *a, const Item *b) {{
        if ({condition}) {{
            return 1;
        }}
        return 0;
    }}
    """
    assert scan(code) == []


def test_short_circuit_or_false_path_is_safe():
    code = f"""
    {STRUCT}
    int f(const Item *a, const Item *b) {{
        if ((a == 0) || (b == 0) || ((a->type & 0xFF) != (b->type & 0xFF))) {{
            return 0;
        }}
        return a->type;
    }}
    """
    assert scan(code) == []


def test_or_true_path_does_not_claim_known_null():
    code = f"""
    {STRUCT}
    int f(Item *a, Item *b) {{
        if ((a == 0) || (b == 0)) {{
            return a->type;
        }}
        return 0;
    }}
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "known to be NULL" not in issues[0].message
    assert "without a preceding NULL check" in issues[0].message


def test_callee_is_style_predicate_guards_getter():
    code = f"""
    {STRUCT}
    int IsString(const Item *item) {{
        if (item == 0) return 0;
        return (item->type & 0xFF) == 4;
    }}
    char *GetStringValue(const Item *item) {{
        if (!IsString(item)) {{
            return 0;
        }}
        return item->valuestring;
    }}
    """
    summaries = analyze_function_summaries(CASTParser().parse(code))
    assert summaries["IsString"].truthy_implies_nonnull_params == {0}
    assert scan(code) == []


def test_cannot_access_macro_does_not_prove_null_or_miss_guard():
    code = f"""
    {STRUCT}
    #define can_access_at_index(buffer, index) ((buffer != 0) && ((buffer)->offset + (index) < (buffer)->length))
    #define cannot_access_at_index(buffer, index) (!can_access_at_index(buffer, index))
    char get_at(Item *buffer, unsigned index) {{
        if (cannot_access_at_index(buffer, index)) {{
            return 0;
        }}
        return buffer->content[buffer->offset + index];
    }}
    """
    issues = scan(code)
    assert issues == []
    assert all("known to be NULL" not in i.message for i in issues)


def test_public_setter_without_guard_remains_tp():
    code = f"""
    {STRUCT}
    double SetNumberHelper(Item *object, double number) {{
        object->valuedouble = number;
        return number;
    }}
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "object" in issues[0].message
