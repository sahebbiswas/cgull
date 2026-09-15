from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cgull import CGullScanner
from cgull.analysis_session import analysis_session_for
from cgull.ast_analyzer import CASTParser
from cgull.cfg.call_graph import build_translation_unit_call_graph
from cgull.cfg.construction import (
    build_cfg,
    build_cfg_uncached,
    find_function_def,
)
import cgull.cfg.construction as construction


def _parse(source: str):
    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    assert ctx.pycparser_ast is not None
    return ctx


def _topology(cfg):
    return {
        node_id: (event.kind, tuple(event.successors))
        for node_id, event in sorted(cfg.nodes.items())
    }


def test_session_builds_structural_cfg_once_per_function_and_reuses_call_graph_instances():
    ctx = _parse(
        "int leaf(void) { return 1; }\n"
        "int top(void) { return leaf(); }\n"
    )

    with patch(
        "cgull.cfg.construction.build_cfg_uncached",
        wraps=construction.build_cfg_uncached,
    ) as uncached_builder:
        session = analysis_session_for(ctx)
        graph = session.call_graph

        assert session.cfg("leaf") is graph.function("leaf").cfg
        assert session.cfg("top") is graph.function("top").cfg
        assert build_translation_unit_call_graph(ctx) is graph

        for name in ("leaf", "top"):
            funcdef = find_function_def(ctx.pycparser_ast, name)
            assert funcdef is session.function_def(name)
            first = build_cfg(funcdef, line_map=ctx.line_map)
            second = build_cfg(funcdef, line_map=ctx.line_map)
            assert first is not second
            assert first is not session.cfg(name)
            assert _topology(first) == _topology(session.cfg(name))

        assert uncached_builder.call_count == 2
        assert session.cfg_construction_count == 2
        assert session.cfg_construction_seconds >= 0.0


def test_concurrent_cfg_requests_publish_one_canonical_instance():
    ctx = _parse("int f(int x) { return x + 1; }\n")
    session = analysis_session_for(ctx)

    with ThreadPoolExecutor(max_workers=8) as executor:
        cfgs = list(executor.map(lambda _: session.cfg("f"), range(32)))

    assert cfgs
    assert all(cfg is cfgs[0] for cfg in cfgs)
    assert session.call_graph.function("f").cfg is cfgs[0]
    assert session.cfg_construction_count == 1


def test_full_rule_scan_structurally_builds_each_function_at_most_once():
    source = (
        "int helper(int value) { return value + 1; }\n"
        "int top(int *p, int flag) {\n"
        "    int value = helper(flag);\n"
        "    if (p && flag) value += *p;\n"
        "    return value;\n"
        "}\n"
    )

    with patch(
        "cgull.cfg.construction.build_cfg_uncached",
        wraps=construction.build_cfg_uncached,
    ) as uncached_builder:
        result = CGullScanner().scan_text(source, file_path="issue490.c", quiet=True)

    assert result.scanned_files_count == 1
    assert uncached_builder.call_count <= 2


def test_mutable_dataflow_on_analysis_cfg_does_not_leak_into_canonical_cfg():
    ctx = _parse(
        "int f(int *p, int flag) {\n"
        "    int value = 0;\n"
        "    if (flag) value = *p;\n"
        "    return value;\n"
        "}\n"
    )
    session = analysis_session_for(ctx)
    canonical = session.cfg("f")
    mutable = session.analysis_cfg("f")

    assert mutable is not canonical
    mutable.nodes[mutable.entry].writes.add("__probe__")
    assert "__probe__" not in canonical.nodes[canonical.entry].writes

    mutable.analyze_dataflow()
    assert hasattr(mutable, "node_facts")
    assert not hasattr(canonical, "node_facts")
    assert all(not block.nullness_in for block in canonical.blocks.values())
    assert all(not block.init_in for block in canonical.blocks.values())
    assert all(not block.alloc_in for block in canonical.blocks.values())


def test_parameterized_cfg_reapplies_event_semantics_without_rebuilding_topology():
    ctx = _parse(
        "void release(int *p);\n"
        "void f(int *p) { release(p); }\n"
    )
    session = analysis_session_for(ctx)
    canonical = session.cfg("f")
    funcdef = session.function_def("f")

    custom = build_cfg(
        funcdef,
        dealloc_funcs={"release"},
        line_map=ctx.line_map,
    )

    assert _topology(custom) == _topology(canonical)
    assert any("p" in event.freed for event in custom.nodes.values())
    assert all("p" not in event.freed for event in canonical.nodes.values())


def test_uncached_escape_hatch_remains_available_for_intentional_fresh_construction():
    ctx = _parse("int f(void) { return 0; }\n")
    session = analysis_session_for(ctx)
    funcdef = session.function_def("f")

    cached_view = build_cfg(funcdef, line_map=ctx.line_map)
    uncached = build_cfg_uncached(funcdef, line_map=ctx.line_map)

    assert uncached is not cached_view
    assert _topology(uncached) == _topology(cached_view)
