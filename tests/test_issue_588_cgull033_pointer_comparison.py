"""CGULL-033 is about integer signedness, not pointer comparisons (#588)."""

import pytest

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id

HEADER = "#include <string.h>\n#include <stddef.h>\ntypedef struct cJSON { char *valuestring; } cJSON;\n"


def scan(code):
    scanner = CGullScanner(
        rules=[get_rule_by_id("CGULL-033")],
        engine_mode=AnalysisEngine.AST,
    )
    return scanner.scan_text(HEADER + code, "issue_588.c").issues


def test_cjson_overlap_check_is_not_reported():
    code = """
    int overlaps(cJSON *object, const char *valuestring)
    {
        size_t v1_len = strlen(valuestring);
        size_t v2_len = strlen(object->valuestring);
        if (!( valuestring + v1_len < object->valuestring || object->valuestring + v2_len < valuestring ))
        {
            return 0;
        }
        return 1;
    }
    """
    assert scan(code) == []


@pytest.mark.parametrize(
    "condition",
    [
        "p + n < end",
        "end > p + n",
        "p + n <= end",
        "n + p < end",
        "buf + n < end",
        "p < end",
        "(p + n) >= end",
        "p != end || p + n < end",
    ],
)
def test_pointer_relational_comparisons_are_not_integer_mismatches(condition):
    code = f"""
    int f(char *p, char *end, size_t n)
    {{
        char buf[16];
        if ({condition}) {{
            return 1;
        }}
        return 0;
    }}
    """
    assert scan(code) == []


def test_local_and_global_pointers_are_not_integer_operands():
    code = """
    char *g_cursor;
    int f(char *base, size_t n)
    {
        char *limit = base + n;
        size_t used = n;
        if (g_cursor + used < limit)
        {
            return 1;
        }
        return 0;
    }
    """
    assert scan(code) == []


@pytest.mark.parametrize(
    "condition, signed_name, unsigned_name",
    [
        ("i < len", "i", "len"),
        ("len > i", "i", "len"),
        ("i <= len", "i", "len"),
        ("i == len", "i", "len"),
    ],
)
def test_genuine_signed_unsigned_comparisons_still_report(condition, signed_name, unsigned_name):
    code = f"""
    int f(int i, size_t len)
    {{
        if ({condition}) {{
            return 1;
        }}
        return 0;
    }}
    """
    issues = scan(code)
    assert len(issues) == 1
    assert issues[0].rule_id == "CGULL-033"
    assert f"signed operand '{signed_name}'" in issues[0].message
    assert f"unsigned operand '{unsigned_name}'" in issues[0].message


def test_integer_comparison_still_reports_next_to_pointer_code():
    code = """
    int f(cJSON *object, const char *s, int i, size_t len)
    {
        if (s + len < object->valuestring) { return 1; }
        if (i < len) { return 2; }
        return 0;
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "'i'" in issues[0].message and "'len'" in issues[0].message


def test_sizeof_of_an_array_is_still_unsigned():
    code = """
    int f(int idx)
    {
        char buf[100];
        if (idx < sizeof(buf)) { return buf[idx]; }
        return 0;
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "'idx'" in issues[0].message


def test_dereferenced_char_pointer_is_still_an_integer_operand():
    code = """
    int f(const char *p, size_t len)
    {
        if (*p < len) { return 1; }
        return 0;
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "'p'" in issues[0].message


def test_reverse_loop_findings_are_unchanged():
    code = """
    void f(size_t len)
    {
        for (size_t i = len; i >= 0; i--) { (void)i; }
    }
    """
    issues = scan(code)
    assert len(issues) == 1
    assert "Infinite Loop Risk" in issues[0].message
