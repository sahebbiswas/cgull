"""Session-owned immutable AST facts and replaceable summary-effect overlays.

ASTs and source maps are read-only for the lifetime of a session. Cache keys own
AST references and normalized effect sets; no analysis view receives mutable
cache state. Only the last overlay per key is retained, bounding fixed-point
storage independently of the number of summary iterations.
"""

from dataclasses import dataclass
from types import MappingProxyType
from threading import RLock

from ..ast_analyzer import _PRELUDE_LINE_COUNT, _format_pycparser_expr, _map_line
from . import ast_events as ast
from .expression_effects import expression_read_write_sets
from .model import Nullness


def _freeze(payload):
    return tuple(
        frozenset(value) if isinstance(value, set)
        else MappingProxyType(dict(value)) if isinstance(value, dict)
        else value
        for value in payload
    )


@dataclass(frozen=True)
class _Call:
    callee: str
    arguments: tuple[str | None, ...]
    target: str | None = None
    value_producing: bool = False
    line: int = 1


def _call(node, target=None, value_producing=False, *, line_map=None, default_line=1):
    coord = getattr(node, "coord", None)
    line = (_map_line(max(1, coord.line - _PRELUDE_LINE_COUNT), line_map)
            if coord is not None else default_line)
    return _Call(
        _format_pycparser_expr(node.name),
        tuple(inner.name if type(inner := ast._unwrap_cast(arg)).__name__ == "ID" else None
              for arg in (getattr(node.args, "exprs", None) or ())),
        target, value_producing, line,
    )


def _effect_calls(node, target=None, value_producing=False):
    """Compile the legacy call-effect traversal once, including target binding."""
    if node is None:
        return
    if type(node).__name__ == "FuncCall":
        yield _call(node, target, value_producing)
        for _, child in node.children():
            yield from _effect_calls(child)
    else:
        unwrapped = ast._unwrap_cast(node)
        for _, child in node.children():
            yield from _effect_calls(child, target, value_producing and child is unwrapped)


@dataclass(frozen=True)
class _BaseFacts:
    payload: tuple
    guarded_calls: tuple[_Call, ...]
    effect_calls: tuple[_Call, ...]
    allocation_calls: tuple[tuple[str, tuple[str, ...]], ...]
    targets: frozenset[str]
    callees: tuple[str, ...]


def _base_facts(node, alloc, dealloc, realloc, line_map):
    # With no allocators/summaries this captures only unconditional syntax:
    # reads, writes, frees, dereferences, aliases and direct realloc bindings.
    payload = list(ast._event_payload(
        node, alloc_funcs=set(), dealloc_funcs=dealloc,
        realloc_funcs=realloc, line_map=line_map,
    ))
    kind = payload[0]
    if kind != "FuncCall":
        payload[1], payload[2] = expression_read_write_sets(node)
    payload[10] = {lhs: rhs for lhs, rhs in payload[10].items() if rhs not in alloc}
    coord = getattr(node, "coord", None)
    default_line = (_map_line(max(1, coord.line - _PRELUDE_LINE_COUNT), line_map)
                    if coord is not None else 1)
    # Preserve the legacy traversal subset; downstream analyses apply guards.
    guarded = tuple(_call(call, line_map=line_map, default_line=default_line)
                    for use, call, _ in ast._guarded_expression_uses(node) if use == "call")
    expr = None
    target = None
    if kind == "Decl" and node.name and node.init is not None:
        expr, target = node.init, str(node.name)
    elif kind == "Assignment":
        expr = node.rvalue
        target = next(iter(ast._assignment_target(node.lvalue)), None)
    effects = tuple(_effect_calls(expr, target, True)) if expr is not None else (
        tuple(_effect_calls(node)) if kind == "FuncCall" else ()
    )
    # Preserve the existing allocation-candidate order and first-match policy.
    allocations = tuple(
        (name, tuple(call.arguments[0] for call in effects
                     if call.callee == name and call.arguments and call.arguments[0] is not None))
        for name in ast._call_names(expr)
    )
    callees = tuple(sorted({call.callee for call in guarded + effects}
                           | {name for name, _ in allocations}))
    targets = frozenset({target}) if target is not None else frozenset()
    return _BaseFacts(_freeze(payload), guarded, effects, allocations, targets, callees)


def _summary_key(summary):
    if summary is None:
        return None
    # Copy values, not identity: summaries and their sets can mutate in place.
    return (frozenset(summary.freed_params), frozenset(summary.unsafe_deref_params),
            summary.return_nullness, summary.returns_allocation)


def _overlay(base, summaries, alloc, realloc):
    payload = [set(value) if isinstance(value, frozenset)
               else dict(value) if isinstance(value, MappingProxyType)
               else value for value in base.payload]
    (_, _, _, nulls, maybe_nulls, freed, allocated, derefs, lines, _, _,
     realloc_inputs, bindings) = payload
    for call in base.guarded_calls:
        summary = summaries.get(call.callee)
        if summary is not None:
            for index in sorted(summary.unsafe_deref_params):
                if index < len(call.arguments) and (arg := call.arguments[index]) is not None:
                    lines.setdefault(arg, call.line)
                    derefs.add(arg)
    # The legacy path only applies these effects when the summary map is nonempty.
    if summaries:
        for call in base.effect_calls:
            summary = summaries.get(call.callee)
            if summary is not None:
                for index in summary.freed_params:
                    if index < len(call.arguments) and (arg := call.arguments[index]) is not None:
                        freed.add(arg)
            if call.target:
                if call.callee in alloc or (summary and summary.returns_allocation):
                    allocated.add(call.target)
                    if call.callee in realloc and call.arguments and call.arguments[0] is not None:
                        realloc_inputs.add(call.arguments[0])
                        if call.value_producing:
                            bindings[call.target] = call.arguments[0]
                elif summary:
                    if summary.return_nullness == Nullness.NULL:
                        nulls.add(call.target)
                    elif summary.return_nullness == Nullness.MAYBE_NULL:
                        maybe_nulls.add(call.target)
    for callee, inputs in base.allocation_calls:
        summary = summaries.get(callee)
        if callee in alloc or (summary and summary.returns_allocation):
            allocated.update(base.targets)
            if callee in realloc:
                realloc_inputs.update(inputs)
            break
    return _freeze(payload)


class EventFactsCache:
    """One cache per analysis session/source map, with immutable cached values."""

    def __init__(self, line_map=None):
        self.line_map = line_map
        self._lock = RLock()
        self._bases = {}
        self._overlays = {}

    def payload(self, node, *, alloc_funcs=None, dealloc_funcs=None,
                realloc_funcs=None, summaries=None):
        with self._lock:
            return self._payload(node, alloc_funcs, dealloc_funcs, realloc_funcs, summaries)

    def _payload(self, node, alloc_funcs, dealloc_funcs, realloc_funcs, summaries):
        alloc = frozenset(alloc_funcs if alloc_funcs is not None else
                          ("malloc", "calloc", "realloc", "aligned_alloc"))
        dealloc = frozenset(dealloc_funcs if dealloc_funcs is not None else ("free", "cfree", "vfree"))
        realloc = frozenset(realloc_funcs if realloc_funcs is not None else ("realloc",))
        key = (node, alloc, dealloc, realloc)
        base = self._bases.get(key)
        if base is None:
            base = _base_facts(node, alloc, dealloc, realloc, self.line_map)
            self._bases[key] = base
        if not base.callees:
            return base.payload
        summaries = summaries or {}
        signature = (bool(summaries), tuple(_summary_key(summaries.get(name)) for name in base.callees))
        previous = self._overlays.get(key)
        if previous is None or previous[0] != signature:
            previous = (signature, _overlay(base, summaries, alloc, realloc))
            self._overlays[key] = previous
        return previous[1]
