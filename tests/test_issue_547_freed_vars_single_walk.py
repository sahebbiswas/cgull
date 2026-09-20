"""Focused coverage for issue #547: single-walk _freed_vars collection."""

from pycparser import c_parser

import cgull.cfg.ast_events as ast_events
from cgull.cfg.ast_events import _freed_vars


_PARSER = c_parser.CParser()


def _func_body(source: str, name: str = "f"):
    ast = _PARSER.parse(source)
    func = next(
        ext
        for ext in ast.ext
        if type(ext).__name__ == "FuncDef" and ext.decl.name == name
    )
    return func.body


def _count_func_calls(node) -> int:
    count = 0
    stack = [node]
    while stack:
        current = stack.pop()
        if type(current).__name__ == "FuncCall":
            count += 1
        for _, child in current.children():
            stack.append(child)
    return count


def test_default_deallocators_collect_direct_ids_including_casts():
    body = _func_body(
        """
        void free(void *);
        void cfree(void *);
        void vfree(void *);
        void f(int *p, int *q, int *r) {
            free((void *)p);
            cfree(q);
            vfree(r);
        }
        """
    )
    assert _freed_vars(body) == {"p", "q", "r"}


def test_custom_dealloc_funcs_replace_defaults():
    body = _func_body(
        """
        void free(void *);
        void pool_free(void *);
        void f(int *p, int *q) {
            free(p);
            pool_free(q);
        }
        """
    )
    assert _freed_vars(body, dealloc_funcs={"pool_free"}) == {"q"}
    assert _freed_vars(body) == {"p"}


def test_nested_calls_and_exprlist_unwrap_to_direct_ids_only():
    body = _func_body(
        """
        void free(void *);
        void sink(void *);
        void f(int *p, int *q, int *r) {
            sink(free(p), q);
            free((p, r));
        }
        """
    )
    # Nested free(p) under sink(...); ExprList (p, r) unwraps to last ID r only.
    assert _freed_vars(body) == {"p", "r"}


def test_non_id_arguments_are_ignored():
    body = _func_body(
        """
        void free(void *);
        void f(int *p) {
            free(p + 1);
            free(*p);
        }
        """
    )
    assert _freed_vars(body) == set()


def test_freed_vars_formats_each_callee_once_independent_of_dealloc_count(monkeypatch):
    """Callee formatting must not scale with the configured deallocator set size.

    The previous implementation walked the subtree once per deallocator and
    formatted every FuncCall on each pass. A single walk formats each FuncCall
    callee exactly once regardless of how many dealloc names are configured.
    """
    body = _func_body(
        """
        void free(void *);
        void cfree(void *);
        void vfree(void *);
        void pool_free(void *);
        void release(void *);
        void f(int *p, int *q, int *r) {
            free((void *)p);
            if (q) {
                pool_free(q);
                release(r);
            }
        }
        """
    )
    func_call_count = _count_func_calls(body)
    assert func_call_count == 3

    format_calls = {"n": 0}
    original_format = ast_events._format_pycparser_expr

    def counting_format(expr):
        format_calls["n"] += 1
        return original_format(expr)

    monkeypatch.setattr(ast_events, "_format_pycparser_expr", counting_format)

    small = {"free", "cfree", "vfree"}
    large = small | {f"extra_free_{i}" for i in range(40)} | {"pool_free", "release"}

    format_calls["n"] = 0
    assert _freed_vars(body, dealloc_funcs=small) == {"p"}
    small_formats = format_calls["n"]

    format_calls["n"] = 0
    assert _freed_vars(body, dealloc_funcs=large) == {"p", "q", "r"}
    large_formats = format_calls["n"]

    assert small_formats == func_call_count
    assert large_formats == func_call_count
    assert large_formats == small_formats
