from time import perf_counter

from cgull.cfg.call_graph import CallGraphFunction, build_call_graph
from cgull.cfg.dataflow import StructuredCFG
from cgull.cfg.model import CFGCall, CFGEvent, CFGSourceLocation


def _function(name, *calls, linkage="external", path="unit.c", line=1):
    cfg = StructuredCFG()
    cfg.nodes[1] = CFGEvent(node_id=1, kind="statement", line_number=line, calls=tuple(calls))
    return CallGraphFunction(
        name=name,
        cfg=cfg,
        linkage=linkage,
        source_location=CFGSourceLocation(path, line, 1),
    )


def _direct(name, line=1, path="unit.c"):
    return CFGCall(
        direct_callee=name,
        callee_expression=name,
        source_location=CFGSourceLocation(path, line, 1),
    )


def _indirect(expr="fp", line=1):
    return CFGCall(
        direct_callee=None,
        callee_expression=expr,
        source_location=CFGSourceLocation("unit.c", line, 1),
        is_indirect=True,
    )


def test_acyclic_graph_is_callee_first_and_exposes_queries():
    graph = build_call_graph([
        _function("top", _direct("middle")),
        _function("leaf"),
        _function("middle", _direct("leaf")),
    ])
    assert graph.callees("top") == ("middle",)
    assert graph.callers("leaf") == ("middle",)
    assert graph.bottom_up_sccs == (("leaf",), ("middle",), ("top",))


def test_mutual_and_self_recursion_form_stable_sccs():
    functions = [
        _function("a", _direct("b")),
        _function("b", _direct("a")),
        _function("self", _direct("self")),
    ]
    graph = build_call_graph(functions)
    assert graph.scc_for("a") == ("a", "b")
    assert graph.scc_for("self") == ("self",)
    assert graph.sccs == build_call_graph(reversed(functions)).sccs
    assert graph.bottom_up_sccs == build_call_graph(reversed(functions)).bottom_up_sccs


def test_static_and_header_defined_function_metadata_is_preserved():
    graph = build_call_graph([
        _function("header_helper", path="include/helper.h", line=7),
        _function("static_helper", linkage="internal", line=3),
    ])
    assert graph.function("header_helper").source_location.file_path == "include/helper.h"
    assert graph.function("static_helper").linkage == "internal"


def test_external_and_indirect_calls_remain_unresolved():
    graph = build_call_graph([
        _function("caller", _direct("printf", line=4), _indirect(line=5)),
    ])
    assert graph.edges == ()
    assert [(edge.call.callee_expression, edge.callee) for edge in graph.unresolved_edges] == [
        ("printf", None),
        ("fp", None),
    ]


def test_graph_does_not_resolve_to_definition_outside_supplied_translation_unit():
    graph = build_call_graph([_function("caller", _direct("other_tu_function"))])
    assert graph.callees("caller") == ()
    assert len(graph.unresolved_edges) == 1


def test_repeated_builds_have_identical_graph_order():
    functions = [
        _function("z", _direct("a", line=9), _direct("m", line=3)),
        _function("m"),
        _function("a"),
    ]
    first = build_call_graph(functions)
    second = build_call_graph(list(reversed(functions)))
    assert tuple(function.name for function in first.functions) == tuple(function.name for function in second.functions)
    assert [(edge.caller, edge.callee) for edge in first.edges] == [(edge.caller, edge.callee) for edge in second.edges]
    assert first.sccs == second.sccs
    assert first.bottom_up_sccs == second.bottom_up_sccs


def test_synthetic_1000_function_construction_time_is_reported():
    functions = []
    for index in range(1000):
        calls = (_direct(f"f{index + 1:04d}"),) if index < 999 else ()
        functions.append(_function(f"f{index:04d}", *calls))
    started = perf_counter()
    graph = build_call_graph(functions)
    wall_seconds = perf_counter() - started
    assert len(graph.functions) == 1000
    assert len(graph.edges) == 999
    assert graph.construction_seconds >= 0.0
    assert graph.construction_seconds <= wall_seconds
    print(f"1,000-function TU call graph: {graph.construction_seconds:.6f}s")
