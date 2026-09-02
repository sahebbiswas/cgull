"""Targeted branch coverage for the rule modules called out in issue #225."""

import pytest

from cgull.ast_analyzer import CASTParser
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules.memory_management import (
    DoubleFreeRule,
    MemoryLeakRule,
    MemcpyStructMemberOverflowRule,
)
from cgull.rules.types_and_arrays import (
    ArrayIndexOutOfBoundsRule,
    PointerSubtractionSizeRule,
)


def _scan(rule, code: str):
    return CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID).scan_text(
        code, "issue_225.c"
    ).issues


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("-(2 + 3)", -5),
        ("+(8 >> 1)", 4),
        ("3 * (4 + 2)", 18),
        ("17 / 4", 4),
        ("1 << 5", 32),
        ("8 / 0", None),
        ("1 << 64", None),
        ("unknown + 1", None),
    ],
)
def test_memcpy_const_arithmetic_edge_branches(expr, expected):
    rule = MemcpyStructMemberOverflowRule()
    assert rule._eval_const_arithmetic(expr) == expected


def test_memcpy_pointer_alias_offset_capacity_is_enforced():
    code = r"""
        void *memcpy(void *, const void *, unsigned long);
        void f(const char *src) {
            char buf[16];
            char *p = &buf[8];
            memcpy(p, src, 9);
        }
    """
    issues = _scan(MemcpyStructMemberOverflowRule(), code)
    assert len(issues) == 1
    assert "exceeds destination buffer capacity" in issues[0].message


def test_pointer_subtraction_detects_calloc_second_size_argument():
    code = r"""
        void *calloc(unsigned long, unsigned long);
        void f(int *begin, int *end) {
            void *p = calloc(1, end - begin);
            (void)p;
        }
    """
    issues = _scan(PointerSubtractionSizeRule(), code)
    assert len(issues) == 1
    assert "calloc" in issues[0].message


def test_pointer_subtraction_byte_pointer_and_scaled_difference_are_safe():
    code = r"""
        void *malloc(unsigned long);
        void *memcpy(void *, const void *, unsigned long);
        void f(char *cb, char *ce, int *ib, int *ie, void *dst) {
            memcpy(dst, cb, ce - cb);
            memcpy(dst, ib, (ie - ib) * sizeof(int));
            (void)malloc((ie - ib) * sizeof(*ib));
        }
    """
    assert _scan(PointerSubtractionSizeRule(), code) == []


def test_pointer_subtraction_typedef_pointer_is_detected():
    code = r"""
        typedef unsigned short word_t;
        typedef word_t *word_ptr;
        void *malloc(unsigned long);
        void f(word_ptr begin, word_ptr end) {
            (void)malloc(end - begin);
        }
    """
    issues = _scan(PointerSubtractionSizeRule(), code)
    assert len(issues) == 1


def test_array_index_constant_upper_bound():
    code = r"""
        int upper(void) {
            int a[4];
            return a[4];
        }
        int safe(void) {
            int a[4];
            return a[3];
        }
    """
    issues = _scan(ArrayIndexOutOfBoundsRule(), code)
    assert len(issues) == 1


def test_array_index_ast_unavailable_returns_no_issues():
    ctx = CASTParser().parse("int f(void) { int a[2]; return a[0]; }")
    ctx.has_pycparser = False
    ctx.pycparser_ast = None
    assert ArrayIndexOutOfBoundsRule().scan_ast("issue_225.c", ctx) == []


def test_memory_leak_custom_allocator_and_deallocator_sets():
    rule = MemoryLeakRule(
        extra_alloc_funcs=["pool_alloc"],
        extra_realloc_funcs=["pool_resize"],
        extra_dealloc_funcs=["pool_free"],
    )
    assert {"pool_alloc", "pool_resize"} <= rule.alloc_funcs
    assert "pool_resize" in rule.realloc_funcs
    assert "pool_free" in rule.dealloc_funcs


def test_memory_leak_return_transfer_is_safe_but_dropped_allocation_is_reported():
    code = r"""
        void *malloc(unsigned long);
        void *give(void) {
            void *p = malloc(16);
            return p;
        }
        void drop(void) {
            void *p = malloc(16);
            (void)p;
        }
    """
    issues = _scan(MemoryLeakRule(), code)
    assert len(issues) == 1
    assert "Memory leak" in issues[0].message


def test_double_free_custom_deallocator_and_reassignment_guard():
    rule = DoubleFreeRule(extra_dealloc_funcs=["release"])
    assert "release" in rule.dealloc_funcs

    code = r"""
        void free(void *);
        void f(void *p) {
            free(p);
            free(p);
        }
        void safe(void *p) {
            free(p);
            p = 0;
            free(p);
        }
    """
    issues = _scan(rule, code)
    assert len(issues) == 1
    assert "Double Free" in issues[0].message
