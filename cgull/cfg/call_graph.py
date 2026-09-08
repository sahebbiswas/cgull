"""Deterministic translation-unit call graph construction."""

from dataclasses import dataclass
from heapq import heappop, heappush
from time import perf_counter
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from ..ast_analyzer import _PRELUDE_LINE_COUNT, _map_line
from .construction import build_cfg, find_function_def
from .dataflow import StructuredCFG
from .indirect_calls import resolve_indirect_calls
from .model import CFGCall, CFGSourceLocation


@dataclass(frozen=True)
class CallGraphFunction:
    name: str
    cfg: StructuredCFG
    linkage: str = "external"
    source_location: Optional[CFGSourceLocation] = None


@dataclass(frozen=True)
class CallGraphEdge:
    caller: str
    callee: Optional[str]
    call: CFGCall

    @property
    def is_resolved(self) -> bool:
        return self.callee is not None


class TranslationUnitCallGraph:
    def __init__(self, functions, edges, unresolved_edges, sccs, bottom_up_sccs, construction_seconds):
        self.functions = tuple(functions)
        self.edges = tuple(edges)
        self.unresolved_edges = tuple(unresolved_edges)
        self.sccs = tuple(tuple(c) for c in sccs)
        self.bottom_up_sccs = tuple(tuple(c) for c in bottom_up_sccs)
        self.construction_seconds = construction_seconds
        self._by_name = {f.name: f for f in self.functions}
        callees = {name: [] for name in self._by_name}
        callers = {name: [] for name in self._by_name}
        for edge in self.edges:
            if edge.callee is not None:
                callees[edge.caller].append(edge.callee)
                callers[edge.callee].append(edge.caller)
        self._callees = {k: tuple(sorted(set(v))) for k, v in callees.items()}
        self._callers = {k: tuple(sorted(set(v))) for k, v in callers.items()}
        self._scc_by_function = {name: i for i, component in enumerate(self.sccs) for name in component}

    def function(self, name):
        return self._by_name.get(name)

    def callers(self, name):
        return self._callers.get(name, ())

    def callees(self, name):
        return self._callees.get(name, ())

    def scc_for(self, name):
        index = self._scc_by_function.get(name)
        return self.sccs[index] if index is not None else ()


def _call_sort_key(call: CFGCall) -> Tuple[Any, ...]:
    loc = call.source_location
    return (
        loc.file_path if loc and loc.file_path else "",
        loc.line_number if loc else 0,
        loc.column_number if loc else 0,
        call.direct_callee or "",
        call.callee_expression,
        call.actual_arguments,
        call.result_target or "",
        call.is_indirect,
        call.resolved_callees,
    )


def _strongly_connected_components(names: Sequence[str], adjacency: Mapping[str, Tuple[str, ...]]):
    ordered = tuple(sorted(names))
    seen, finish = set(), []
    for start in ordered:
        if start in seen:
            continue
        seen.add(start)
        frames = [(start, 0)]
        while frames:
            name, index = frames[-1]
            neighbors = adjacency.get(name, ())
            if index < len(neighbors):
                nxt = neighbors[index]
                frames[-1] = (name, index + 1)
                if nxt not in seen:
                    seen.add(nxt)
                    frames.append((nxt, 0))
            else:
                finish.append(name)
                frames.pop()
    reverse = {name: [] for name in ordered}
    for caller in ordered:
        for callee in adjacency.get(caller, ()):
            reverse[callee].append(caller)
    reverse = {name: tuple(sorted(v)) for name, v in reverse.items()}
    assigned, components = set(), []
    for start in reversed(finish):
        if start in assigned:
            continue
        assigned.add(start)
        component, stack = [], [start]
        while stack:
            name = stack.pop()
            component.append(name)
            for caller in reversed(reverse[name]):
                if caller not in assigned:
                    assigned.add(caller)
                    stack.append(caller)
        components.append(tuple(sorted(component)))
    return tuple(sorted(components))


def _bottom_up_scc_order(sccs, adjacency):
    component_of = {name: i for i, component in enumerate(sccs) for name in component}
    outgoing = {i: set() for i in range(len(sccs))}
    predecessors = {i: set() for i in range(len(sccs))}
    for caller, callees in adjacency.items():
        source = component_of[caller]
        for callee in callees:
            target = component_of[callee]
            if source != target:
                outgoing[source].add(target)
                predecessors[target].add(source)
    degree = {i: len(v) for i, v in outgoing.items()}
    ready = []
    for i, value in degree.items():
        if value == 0:
            heappush(ready, (sccs[i], i))
    result = []
    while ready:
        _, i = heappop(ready)
        result.append(sccs[i])
        for pred in sorted(predecessors[i], key=lambda item: sccs[item]):
            degree[pred] -= 1
            if degree[pred] == 0:
                heappush(ready, (sccs[pred], pred))
    return tuple(result)


def build_call_graph(functions: Iterable[CallGraphFunction]) -> TranslationUnitCallGraph:
    """Build a graph, resolving bounded local function-pointer targets first."""
    started = perf_counter()
    ordered_functions = tuple(sorted(functions, key=lambda f: f.name))
    by_name: Dict[str, CallGraphFunction] = {}
    for function in ordered_functions:
        if function.name in by_name:
            raise ValueError(f"duplicate function definition in translation unit: {function.name}")
        by_name[function.name] = function

    for function in ordered_functions:
        resolve_indirect_calls(function.cfg, by_name)

    resolved, unresolved = [], []
    adjacency = {name: set() for name in by_name}
    for function in ordered_functions:
        calls = [call for node_id in sorted(function.cfg.nodes) for call in function.cfg.nodes[node_id].calls]
        for call in sorted(calls, key=_call_sort_key):
            targets = tuple(target for target in call.possible_callees if target in by_name)
            if not targets:
                unresolved.append(CallGraphEdge(function.name, None, call))
                continue
            for callee in targets:
                adjacency[function.name].add(callee)
                resolved.append(CallGraphEdge(function.name, callee, call))

    stable = {name: tuple(sorted(v)) for name, v in adjacency.items()}
    sccs = _strongly_connected_components(tuple(by_name), stable)
    return TranslationUnitCallGraph(
        ordered_functions,
        tuple(resolved),
        tuple(unresolved),
        sccs,
        _bottom_up_scc_order(sccs, stable),
        perf_counter() - started,
    )


def _function_source_location(funcdef: Any, line_map) -> CFGSourceLocation:
    coord = getattr(getattr(funcdef, "decl", None), "coord", None) or getattr(funcdef, "coord", None)
    if coord is None:
        return CFGSourceLocation(None, 1, 0)
    expanded_line = max(1, coord.line - _PRELUDE_LINE_COUNT)
    mapped = line_map.get(expanded_line) if line_map else None
    return CFGSourceLocation(
        getattr(mapped, "file_path", None) if mapped is not None else getattr(coord, "file", None),
        _map_line(expanded_line, line_map),
        getattr(coord, "column", 0) or 0,
    )


def build_translation_unit_call_graph(ast_context: Any) -> TranslationUnitCallGraph:
    if not getattr(ast_context, "has_pycparser", False) or getattr(ast_context, "pycparser_ast", None) is None:
        return build_call_graph(())
    line_map = getattr(ast_context, "line_map", None)
    inputs, seen = [], set()
    for function in sorted(getattr(ast_context, "functions", ()), key=lambda item: item.name):
        if function.name in seen:
            continue
        funcdef = find_function_def(ast_context.pycparser_ast, function.name)
        if funcdef is None:
            continue
        seen.add(function.name)
        storage = set(getattr(getattr(funcdef, "decl", None), "storage", ()) or ())
        inputs.append(CallGraphFunction(
            function.name,
            build_cfg(funcdef, line_map=line_map),
            "internal" if "static" in storage else "external",
            _function_source_location(funcdef, line_map),
        ))
    return build_call_graph(inputs)
