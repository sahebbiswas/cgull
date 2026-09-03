"""Deterministic direct-call graph construction for one expanded translation unit."""

from dataclasses import dataclass
from heapq import heappop, heappush
from time import perf_counter
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from ..ast_analyzer import _PRELUDE_LINE_COUNT, _map_line
from .construction import build_cfg, find_function_def
from .dataflow import StructuredCFG
from .model import CFGCall, CFGSourceLocation


@dataclass(frozen=True)
class CallGraphFunction:
    """One function definition visible in the expanded translation unit."""

    name: str
    cfg: StructuredCFG
    linkage: str = "external"
    source_location: Optional[CFGSourceLocation] = None


@dataclass(frozen=True)
class CallGraphEdge:
    """A call edge emitted by a caller CFG event."""

    caller: str
    callee: Optional[str]
    call: CFGCall

    @property
    def is_resolved(self) -> bool:
        return self.callee is not None


class TranslationUnitCallGraph:
    """Immutable, deterministic call graph for exactly one translation unit."""

    def __init__(
        self,
        functions: Sequence[CallGraphFunction],
        edges: Sequence[CallGraphEdge],
        unresolved_edges: Sequence[CallGraphEdge],
        sccs: Sequence[Sequence[str]],
        bottom_up_sccs: Sequence[Sequence[str]],
        construction_seconds: float,
    ) -> None:
        self.functions = tuple(functions)
        self.edges = tuple(edges)
        self.unresolved_edges = tuple(unresolved_edges)
        self.sccs = tuple(tuple(component) for component in sccs)
        self.bottom_up_sccs = tuple(tuple(component) for component in bottom_up_sccs)
        self.construction_seconds = construction_seconds
        self._by_name = {function.name: function for function in self.functions}
        self._callees = {name: [] for name in self._by_name}
        self._callers = {name: [] for name in self._by_name}
        for edge in self.edges:
            if edge.callee is not None:
                self._callees[edge.caller].append(edge.callee)
                self._callers[edge.callee].append(edge.caller)
        self._callees = {key: tuple(sorted(set(value))) for key, value in self._callees.items()}
        self._callers = {key: tuple(sorted(set(value))) for key, value in self._callers.items()}
        self._scc_by_function = {
            name: component_index
            for component_index, component in enumerate(self.sccs)
            for name in component
        }

    def function(self, name: str) -> Optional[CallGraphFunction]:
        return self._by_name.get(name)

    def callers(self, name: str) -> Tuple[str, ...]:
        return self._callers.get(name, ())

    def callees(self, name: str) -> Tuple[str, ...]:
        return self._callees.get(name, ())

    def scc_for(self, name: str) -> Tuple[str, ...]:
        index = self._scc_by_function.get(name)
        return self.sccs[index] if index is not None else ()


def _call_sort_key(call: CFGCall) -> Tuple[Any, ...]:
    location = call.source_location
    return (
        location.file_path if location and location.file_path else "",
        location.line_number if location else 0,
        location.column_number if location else 0,
        call.direct_callee or "",
        call.callee_expression,
        call.actual_arguments,
        call.result_target or "",
        call.is_indirect,
    )


def _strongly_connected_components(names: Sequence[str], adjacency: Mapping[str, Tuple[str, ...]]) -> Tuple[Tuple[str, ...], ...]:
    """Tarjan SCCs with stable node/edge visitation and stable component order."""
    index = 0
    indices: Dict[str, int] = {}
    lowlinks: Dict[str, int] = {}
    stack = []
    on_stack = set()
    components = []

    def visit(name: str) -> None:
        nonlocal index
        indices[name] = index
        lowlinks[name] = index
        index += 1
        stack.append(name)
        on_stack.add(name)

        for callee in adjacency[name]:
            if callee not in indices:
                visit(callee)
                lowlinks[name] = min(lowlinks[name], lowlinks[callee])
            elif callee in on_stack:
                lowlinks[name] = min(lowlinks[name], indices[callee])

        if lowlinks[name] == indices[name]:
            component = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == name:
                    break
            components.append(tuple(sorted(component)))

    for name in sorted(names):
        if name not in indices:
            visit(name)
    return tuple(sorted(components))


def _bottom_up_scc_order(
    sccs: Sequence[Tuple[str, ...]], adjacency: Mapping[str, Tuple[str, ...]]
) -> Tuple[Tuple[str, ...], ...]:
    """Return SCCs in deterministic callee-before-caller order."""
    component_of = {name: index for index, component in enumerate(sccs) for name in component}
    outgoing = {index: set() for index in range(len(sccs))}
    predecessors = {index: set() for index in range(len(sccs))}
    for caller, callees in adjacency.items():
        source = component_of[caller]
        for callee in callees:
            target = component_of[callee]
            if source != target:
                outgoing[source].add(target)
                predecessors[target].add(source)

    remaining_outdegree = {index: len(targets) for index, targets in outgoing.items()}
    ready = []
    for index, degree in remaining_outdegree.items():
        if degree == 0:
            heappush(ready, (sccs[index], index))

    ordered = []
    while ready:
        _, index = heappop(ready)
        ordered.append(sccs[index])
        for predecessor in sorted(predecessors[index], key=lambda item: sccs[item]):
            remaining_outdegree[predecessor] -= 1
            if remaining_outdegree[predecessor] == 0:
                heappush(ready, (sccs[predecessor], predecessor))
    return tuple(ordered)


def build_call_graph(functions: Iterable[CallGraphFunction]) -> TranslationUnitCallGraph:
    """Build a graph from CFGs belonging to one expanded translation unit.

    Only syntactically direct calls whose spelling names a visible definition are
    resolved. External direct calls and every indirect call remain unresolved.
    """
    started = perf_counter()
    ordered_functions = tuple(sorted(functions, key=lambda function: function.name))
    by_name: Dict[str, CallGraphFunction] = {}
    for function in ordered_functions:
        if function.name in by_name:
            raise ValueError(f"duplicate function definition in translation unit: {function.name}")
        by_name[function.name] = function

    resolved = []
    unresolved = []
    adjacency = {name: set() for name in by_name}
    for function in ordered_functions:
        calls = [call for node_id in sorted(function.cfg.nodes) for call in function.cfg.nodes[node_id].calls]
        for call in sorted(calls, key=_call_sort_key):
            callee = None
            if not call.is_indirect and call.direct_callee in by_name:
                callee = call.direct_callee
                adjacency[function.name].add(callee)
            edge = CallGraphEdge(function.name, callee, call)
            (resolved if callee is not None else unresolved).append(edge)

    stable_adjacency = {name: tuple(sorted(callees)) for name, callees in adjacency.items()}
    sccs = _strongly_connected_components(tuple(by_name), stable_adjacency)
    bottom_up = _bottom_up_scc_order(sccs, stable_adjacency)
    return TranslationUnitCallGraph(
        ordered_functions,
        tuple(resolved),
        tuple(unresolved),
        sccs,
        bottom_up,
        perf_counter() - started,
    )


def _function_source_location(funcdef: Any, line_map: Optional[Dict[int, Any]]) -> CFGSourceLocation:
    coord = getattr(getattr(funcdef, "decl", None), "coord", None) or getattr(funcdef, "coord", None)
    if coord is None:
        return CFGSourceLocation(file_path=None, line_number=1, column_number=0)
    expanded_line = max(1, coord.line - _PRELUDE_LINE_COUNT)
    mapped = line_map.get(expanded_line) if line_map else None
    return CFGSourceLocation(
        file_path=getattr(mapped, "file_path", None) if mapped is not None else getattr(coord, "file", None),
        line_number=_map_line(expanded_line, line_map),
        column_number=getattr(coord, "column", 0) or 0,
    )


def build_translation_unit_call_graph(ast_context: Any) -> TranslationUnitCallGraph:
    """Build the direct-call graph for all pycparser definitions in ``ast_context``."""
    if not getattr(ast_context, "has_pycparser", False) or getattr(ast_context, "pycparser_ast", None) is None:
        return build_call_graph(())

    line_map = getattr(ast_context, "line_map", None)
    inputs = []
    seen = set()
    for function in sorted(getattr(ast_context, "functions", ()), key=lambda item: item.name):
        if function.name in seen:
            continue
        funcdef = find_function_def(ast_context.pycparser_ast, function.name)
        if funcdef is None:
            continue
        seen.add(function.name)
        storage = set(getattr(getattr(funcdef, "decl", None), "storage", ()) or ())
        inputs.append(
            CallGraphFunction(
                name=function.name,
                cfg=build_cfg(funcdef, line_map=line_map),
                linkage="internal" if "static" in storage else "external",
                source_location=_function_source_location(funcdef, line_map),
            )
        )
    return build_call_graph(inputs)
