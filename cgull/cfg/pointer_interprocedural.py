"""Call-site pointer requirements evaluated by the shared SCC engine.

Requirements retain byte offsets relative to formals, not merged caller
guarantees. Instantiating them with each call's pre-transfer facts preserves
context through wrappers without allowing a safe caller to bless another.
"""

from dataclasses import dataclass, replace

from pycparser import c_ast

from .call_graph import build_translation_unit_call_graph
from .fixed_point import FiniteLattice, SCCFixedPointEngine
from .pointer_ranges import (
    OffsetInterval, PointerRangeEvent,
    TranslationUnitPointerRangeResult,
)


@dataclass(frozen=True)
class PointerRangeRequirement:
    parameter: int
    offset: OffsetInterval
    width: int | None
    write: bool = False
    is_access: bool = False
    intervals: tuple = ()


@dataclass(frozen=True)
class PointerRangeSummary:
    requirements: frozenset = frozenset()
    unknown: bool = False


class _Requirements(FiniteLattice):
    # Bound both the number of distinct requirements and the integer universe.
    # Recursive pointer shifts otherwise create an infinite ascending chain.
    max_height = 130

    def bottom(self, symbol):
        return PointerRangeSummary()

    def join(self, left, right):
        requirements = left.requirements | right.requirements
        if left.unknown or right.unknown or len(requirements) > 128 or any(
            abs(value) > (1 << 63) - 1
            for requirement in requirements
            for value in (requirement.offset.lower, requirement.offset.upper,
                          requirement.width)
            if value is not None
        ):
            return PointerRangeSummary(unknown=True)
        return PointerRangeSummary(requirements)

    def unknown(self, symbol, current):
        return PointerRangeSummary(unknown=True)


def _sort_key(requirement):
    return (requirement.parameter, repr(requirement.offset),
            repr(requirement.width), requirement.write, requirement.is_access,
            requirement.intervals)


def _requirement(event, parameters):
    if event.fact.origin not in parameters:
        return None
    return PointerRangeRequirement(
        parameters.index(event.fact.origin), event.fact.offset,
        event.access_width, event.write, event.is_access,
        tuple(sorted(set(event.fact.proven_intervals))),
    )


def _bind(requirement, actual, node):
    if actual.is_unknown and requirement.intervals:
        # A validator inside the callee can anchor even an opaque actual.
        # This identity carries no caller object/extent guarantee.
        coord = getattr(node, 'coord', None)
        actual = replace(actual, origin=f"argument@{coord}:{requirement.parameter}",
                         offset=OffsetInterval.exact(0))
    offset = requirement.offset
    if offset.is_exact:
        fact = actual.shifted(offset.lower)
    elif not offset.is_unknown and not actual.offset.is_unknown:
        fact = replace(actual, offset=OffsetInterval(
            actual.offset.lower + offset.lower,
            actual.offset.upper + offset.upper,
        ), lower_bound=None, upper_bound=None)
    else:
        fact = actual.unknown_offset("UNKNOWN_CALLEE_REQUIREMENT")
    # Callee validators/guards prove intervals relative to its entry value.
    # Their local dependencies cannot escape into the caller's namespace.
    intervals = set(actual.proven_intervals)
    if actual.offset.is_exact:
        intervals.update((lo + actual.offset.lower, hi + actual.offset.lower)
                         for lo, hi in requirement.intervals)
    fact = replace(fact, validated_intervals=tuple(sorted(intervals)), guarded_intervals=())
    return PointerRangeEvent(node, fact, requirement.width,
                             requirement.write, requirement.is_access,
                             getattr(node.name, 'name', None))


def _call_events(result, summaries, parameters):
    events = []
    for node, callee, actuals in result.calls:
        summary = summaries.get(callee)
        if summary is None:
            continue  # No inferred guarantee for unresolved/indirect calls.
        requirements = summary.requirements
        if summary.unknown:
            requirements = frozenset(
                PointerRangeRequirement(index, OffsetInterval(), None, is_access=True)
                for index in range(len(parameters[callee]))
            )
        for requirement in sorted(requirements, key=_sort_key):
            if requirement.parameter < len(actuals):
                events.append(_bind(requirement, actuals[requirement.parameter], node))
    return tuple(events)


def _address_taken(ast, names):
    escaped = set()

    class Visitor(c_ast.NodeVisitor):
        def visit_FuncCall(self, node):
            if not isinstance(node.name, c_ast.ID):
                self.visit(node.name)
            if node.args is not None:
                self.visit(node.args)

        def visit_ID(self, node):
            if node.name in names:
                escaped.add(node.name)

    Visitor().visit(ast)
    return escaped


def propagate_pointer_requirements(ast_ctx, results, *, call_graph=None):
    graph = call_graph or build_translation_unit_call_graph(ast_ctx)
    parameters = {fn.name: tuple(p.name for p in fn.parameters)
                  for fn in ast_ctx.functions if fn.name in results}
    local = {name: tuple(result.events) for name, result in results.items()}

    def transfer(name, summaries, config):
        if name not in results:
            return PointerRangeSummary(unknown=True)
        events = local[name] + _call_events(results[name], summaries, parameters)
        requirements = frozenset(
            requirement for event in events
            if (requirement := _requirement(event, parameters[name])) is not None
        )
        return PointerRangeSummary(requirements)

    fixed = SCCFixedPointEngine(graph, _Requirements()).run(transfer)
    escaped = _address_taken(ast_ctx.pycparser_ast, set(results))
    calls = {}
    for name, result in sorted(results.items()):
        calls[name] = _call_events(result, fixed.facts, parameters)
        events = local[name] + calls[name]
        function = graph.function(name)
        if function and function.linkage == "internal" and graph.callers(name) and name not in escaped:
            # Evaluate formal-dependent events at callers. Local-object events
            # stay here. Public/address-taken functions retain an unknown entry.
            events = tuple(event for event in events if event.fact.origin not in parameters[name])
        result.events = events
    return TranslationUnitPointerRangeResult(
        dict(sorted(results.items())), fixed.facts, calls,
        fixed.diagnostics, fixed.iterations_by_scc,
    )
