"""Cached event facts must remain equivalent to uncached CFG semantics."""
from unittest.mock import patch

import pytest
from pycparser import c_parser

from cgull.ast_analyzer import CASTParser
from cgull.analysis_session import AnalysisSession
from cgull.cfg import ast_events, event_cache
from cgull.cfg.construction import apply_cfg_event_semantics, clone_structural_cfg
from cgull.cfg.event_cache import EventFactsCache
from cgull.cfg.expression_effects import expression_read_write_sets
from cgull.cfg.model import FunctionSummary, Nullness


SOURCE = """
void f(int *p, int *q) {
    int *a = wrap(p);
    int *b = resize(p, 8);
    int *c = alloc(8);
    int *d = p;
    a = wrap(resize(q, 4));
    b = (int *)resize(p, 16);
    p && consume(p);
    consume(p ? p : q);
    release(p);
    assert(q);
    *q = *p;
    return;
}
"""


@pytest.mark.parametrize("effects", [
    {},
    dict(alloc_funcs=set(), dealloc_funcs=set(), realloc_funcs=set()),
    dict(alloc_funcs={"alloc", "resize"}, dealloc_funcs={"release"}, realloc_funcs={"resize"}),
    dict(alloc_funcs={"resize", "p"}, dealloc_funcs={"release", "consume"}, realloc_funcs={"resize"}),
])
def test_cached_payload_matches_uncached_across_summary_changes(effects):
    tree = c_parser.CParser().parse(SOURCE)
    line_map = {1: 901, 2: 902}
    cache = EventFactsCache(line_map)
    summaries = {"wrap": FunctionSummary(), "consume": FunctionSummary()}
    for phase in range(5):
        if phase == 1:
            summaries["wrap"].returns_allocation = True
            summaries["consume"].unsafe_deref_params.add(0)
            summaries["wrap"].freed_params.add(0)
        elif phase == 2:
            summaries["wrap"].returns_allocation = False
            summaries["wrap"].return_nullness = Nullness.NULL
            summaries["consume"].unsafe_deref_params.clear()
        elif phase == 3:
            summaries["wrap"].return_nullness = Nullness.MAYBE_NULL
        elif phase == 4:
            summaries.clear()
        for node in tree.ext[0].body.block_items:
            expected = list(ast_events._event_payload(node, summaries=summaries, line_map=line_map, **effects))
            if expected[0] != "FuncCall":
                expected[1:3] = expression_read_write_sets(node)
            actual = cache.payload(node, summaries=summaries, **effects)
            assert actual == tuple(expected)


def test_base_work_once_and_only_relevant_overlay_invalidated():
    node = c_parser.CParser().parse(SOURCE).ext[0].body.block_items[0]
    cache = EventFactsCache()
    summaries = {"wrap": FunctionSummary()}
    with patch("cgull.cfg.event_cache._base_facts", wraps=event_cache._base_facts) as build:
        first = cache.payload(node, summaries=summaries)
        summaries["unrelated"] = FunctionSummary(returns_allocation=True)
        assert cache.payload(node, summaries=summaries) is first
        summaries["wrap"].returns_allocation = True
        second = cache.payload(node, summaries=summaries)
        assert second is not first
        assert second[6] == {"a"}
        assert first[6] == set()
        assert build.call_count == 1
        # A changed static effect set gets a separate compatible base.
        cache.payload(node, summaries=summaries, dealloc_funcs={"wrap"})
        assert build.call_count == 2
    with pytest.raises(AttributeError):
        second[6].add("corruption")
    with pytest.raises(TypeError):
        second[8]["corruption"] = 1


def test_session_views_and_source_maps_are_isolated():
    context = CASTParser().parse(SOURCE)
    context.line_map = {line: 42 for line in range(1, 100)}
    session = AnalysisSession(context)
    effects = dict(alloc_funcs={"alloc", "resize"}, dealloc_funcs={"release"},
                   realloc_funcs={"resize"}, summaries={"wrap": FunctionSummary(returns_allocation=True)})
    first = session.analysis_cfg("f", **effects)
    expected = apply_cfg_event_semantics(clone_structural_cfg(session.cfg("f")), line_map=context.line_map, **effects)
    attrs = ("reads", "writes", "null_writes", "maybe_null_writes", "freed", "allocated",
             "derefs", "deref_lines", "asserted", "alias_writes", "realloc_inputs", "realloc_bindings")
    for key, event in first.nodes.items():
        for attr in attrs:
            assert getattr(event, attr) == getattr(expected.nodes[key], attr)
            value = getattr(event, attr)
            if isinstance(value, dict):
                value["corruption"] = 123
            elif isinstance(value, set):
                value.add("corruption")
    second = session.analysis_cfg("f", **effects)
    for key, event in second.nodes.items():
        for attr in attrs:
            assert getattr(event, attr) == getattr(expected.nodes[key], attr)
    old_cache = session._event_facts_cache
    other = AnalysisSession(context)
    other.analysis_cfg("f", **effects)
    assert other._event_facts_cache is not old_cache
    context.line_map = {line: 84 for line in range(1, 100)}
    third = session.analysis_cfg("f", **effects)
    assert session._event_facts_cache is not old_cache
    assert any(84 in event.deref_lines.values() for event in third.nodes.values())


@pytest.mark.parametrize("statement", [
    "int *a = (int *)wrap(resize(p, 4));",
    "a = p ? wrap(q) : resize(p, 4);",
    "a += wrap(p);",
    "*p = wrap(q);",
    "wrap(release(p), consume(q));",
    "return wrap(p);",
    "int *a = (release(p), wrap(q));",
    "int *a = &p[2];",
    "int *a = 0;",
    "assert(p && consume(p));",
    "a = (*callback)(p);",
])
def test_nested_and_value_producing_calls_match_legacy(statement):
    node = c_parser.CParser().parse("void f() { " + statement + " }").ext[0].body.block_items[0]
    cache = EventFactsCache()
    effects = dict(alloc_funcs={"resize"}, dealloc_funcs={"release"}, realloc_funcs={"resize"})
    for summaries in ({}, {"irrelevant": FunctionSummary()}, {
        "wrap": FunctionSummary(freed_params={0}, returns_allocation=True),
        "consume": FunctionSummary(unsafe_deref_params={0}),
        "resize": FunctionSummary(return_nullness=Nullness.NULL),
    }):
        expected = list(ast_events._event_payload(node, summaries=summaries, **effects))
        if expected[0] != "FuncCall":
            expected[1:3] = expression_read_write_sets(node)
        assert cache.payload(node, summaries=summaries, **effects) == tuple(expected)


def test_concurrent_analysis_views_build_each_compatible_base_once():
    from concurrent.futures import ThreadPoolExecutor

    session = AnalysisSession(CASTParser().parse("int f(int *p) { return *p; }"))
    session.cfg("f")
    with patch("cgull.cfg.event_cache._base_facts", wraps=event_cache._base_facts) as build:
        with ThreadPoolExecutor(max_workers=4) as executor:
            views = list(executor.map(lambda _: session.analysis_cfg("f", summaries={}), range(16)))
    assert build.call_count == 1
    assert len({id(view) for view in views}) == 16


def test_recursive_summaries_keep_explicit_cache_with_ambiguous_session_ownership():
    from cgull.cfg import construction, summaries

    context = CASTParser().parse("""
        void release(int *p) { free(p); }
        int recur(int *p, int n) {
            if (n) return recur(p, n - 1);
            release(p);
            return *p;
        }
    """)
    first = AnalysisSession(context)
    second = AnalysisSession(context)
    # Keep both owners alive: the legacy build_cfg entry point must not guess.
    assert first.function_def("recur") is second.function_def("recur")
    with patch("cgull.cfg.construction.apply_cfg_event_semantics",
               wraps=construction.apply_cfg_event_semantics) as apply:
        actual = first._ensure_function_summaries()
    assert apply.call_count > 0
    assert all(call.kwargs["event_cache"] is first._event_facts_cache for call in apply.call_args_list)
    alloc, dealloc, realloc = first._memory_effect_sets()
    expected = summaries.analyze_function_summaries_detailed(
        context, alloc_funcs=alloc, dealloc_funcs=dealloc, realloc_funcs=realloc,
        call_graph=first.call_graph, call_effects=first.semantic_models.call_effects,
    )
    assert summaries.serialize_function_summaries(actual.summaries) == summaries.serialize_function_summaries(expected.summaries)
    assert actual.iterations_by_scc == expected.iterations_by_scc
    assert actual.iterations_by_scc[("recur",)] > 1
