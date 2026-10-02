"""Conservative intra-TU integer range summaries for direct helper calls."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import re
from typing import Dict, Mapping, Optional, Set, Tuple

from .construction import find_function_def
from .integer_ranges import (
    IntegerRange,
    IntegerRangeAnalysis,
    _apply,
    _condition,
    _condition_truth,
    _constraints,
    _descendants,
    _merge,
    _name,
    _transfer,
    _widen,
    integer_type_range,
)

__all__ = [
    "IntegerRangeSummaryIndex",
    "analyze_integer_ranges",
    "integer_range_summary_index",
]


@dataclass(frozen=True)
class IntegerRangeSummaryIndex:
    """Per-context direct-call range summaries used by CGULL-049."""

    parameter_ranges: Mapping[str, Mapping[str, IntegerRange]]
    return_ranges: Mapping[str, IntegerRange]
    analyses: Mapping[str, IntegerRangeAnalysis]
    converged: bool
    iterations: int


class _SummaryAwareIntegerRangeAnalysis(IntegerRangeAnalysis):
    def __init__(
        self,
        ast_ctx,
        function,
        cfg,
        facts_before,
        return_ranges: Mapping[str, IntegerRange],
    ) -> None:
        super().__init__(ast_ctx, function, cfg, facts_before)
        self._return_ranges = return_ranges

    def range_for_expression(self, expression, at_node=None) -> Optional[IntegerRange]:
        callee = _direct_call_name(expression)
        if callee is not None:
            summary = self._return_ranges.get(callee)
            if summary is not None:
                return summary
        return super().range_for_expression(expression, at_node)


def _direct_call_name(node) -> Optional[str]:
    if node is None or type(node).__name__ != "FuncCall":
        return None
    name = getattr(node, "name", None)
    return str(name.name) if type(name).__name__ == "ID" else None


def _function_models(ast_ctx):
    return {fn.name: fn for fn in getattr(ast_ctx, "functions", ())}


def _function_defs(ast_ctx):
    result = {}
    for name in _function_models(ast_ctx):
        funcdef = find_function_def(getattr(ast_ctx, "pycparser_ast", None), name)
        if funcdef is not None:
            result[name] = funcdef
    return result


def _collect_calls(funcdefs) -> Tuple[Dict[str, Set[str]], Dict[str, list]]:
    from pycparser import c_ast

    graph: Dict[str, Set[str]] = {name: set() for name in funcdefs}
    callsites: Dict[str, list] = {name: [] for name in funcdefs}

    class Visitor(c_ast.NodeVisitor):
        def __init__(self, caller: str) -> None:
            self.caller = caller

        def visit_FuncCall(self, node):
            callee = _direct_call_name(node)
            if callee in funcdefs:
                graph[self.caller].add(callee)
                callsites[callee].append((self.caller, node))
            self.generic_visit(node)

    for caller, funcdef in funcdefs.items():
        Visitor(caller).visit(funcdef.body)
    return graph, callsites


def _recursive_functions(graph: Mapping[str, Set[str]]) -> Set[str]:
    recursive: Set[str] = set()

    def reaches(start: str, current: str, seen: Set[str]) -> bool:
        for callee in graph.get(current, ()):
            if callee == start:
                return True
            if callee in seen:
                continue
            seen.add(callee)
            if reaches(start, callee, seen):
                return True
        return False

    for name in graph:
        if reaches(name, name, {name}):
            recursive.add(name)
    return recursive


def _escaped_function_references(ast_ctx, funcdefs) -> Set[str]:
    """Find function designators used anywhere other than a direct call target."""

    names = set(funcdefs)
    escaped: Set[str] = set()

    def walk(node, parent=None) -> None:
        if node is None:
            return
        if type(node).__name__ == "ID" and str(node.name) in names:
            if not (type(parent).__name__ == "FuncCall" and getattr(parent, "name", None) is node):
                escaped.add(str(node.name))
        for _, child in node.children():
            walk(child, node)

    walk(getattr(ast_ctx, "pycparser_ast", None))
    return escaped


def _private_static(funcdef) -> bool:
    return "static" in (getattr(getattr(funcdef, "decl", None), "storage", ()) or ())


def _clamp_to_type(value: IntegerRange, type_name: str, ast_ctx) -> Optional[IntegerRange]:
    destination = integer_type_range(type_name, ast_ctx)
    if destination is None:
        return None
    if value.fits_within(destination):
        return value
    return destination


def _seed_ranges(ast_ctx, fn, requested: Mapping[str, IntegerRange]) -> Dict[str, IntegerRange]:
    parameters = {parameter.name: parameter for parameter in getattr(fn, "parameters", ())}
    result: Dict[str, IntegerRange] = {}
    for name, value in requested.items():
        parameter = parameters.get(name)
        if parameter is None or parameter.is_pointer or parameter.is_array:
            continue
        clamped = _clamp_to_type(value, parameter.type_name, ast_ctx)
        if clamped is not None:
            result[name] = clamped
    return result


def _call_assignment_range(node, return_ranges: Mapping[str, IntegerRange]) -> Optional[IntegerRange]:
    callee = _direct_call_name(node)
    return return_ranges.get(callee) if callee is not None else None


def _restore_direct_call_assignment(
    event,
    result: Dict[str, IntegerRange],
    ast_ctx,
    fn,
    exposed: Set[str],
    unstable: Set[str],
    return_ranges: Mapping[str, IntegerRange],
) -> Dict[str, IntegerRange]:
    """Propagate summarized direct-call results through simple local assignments."""

    node = getattr(event, "_ast_node", None)
    if node is None:
        return result
    target = None
    source = None
    if type(node).__name__ == "Decl" and getattr(node, "name", None):
        target = str(node.name)
        source = getattr(node, "init", None)
        variable = getattr(fn, "variables", {}).get(target)
        destination_type = getattr(variable, "type_name", None)
    elif type(node).__name__ == "Assignment" and getattr(node, "op", None) == "=":
        target = _name(getattr(node, "lvalue", None))
        source = getattr(node, "rvalue", None)
        variable = getattr(fn, "variables", {}).get(target) if target else None
        destination_type = getattr(variable, "type_name", None)
    else:
        return result

    if not target or target in exposed or target in unstable or not destination_type:
        return result
    value = _call_assignment_range(source, return_ranges)
    if value is None:
        return result
    clamped = _clamp_to_type(value, destination_type, ast_ctx)
    if clamped is not None:
        result[target] = clamped
    return result


def _analyze_seeded(
    ast_ctx,
    function_name: str,
    entry_ranges: Mapping[str, IntegerRange],
    return_ranges: Mapping[str, IntegerRange],
    *,
    fn=None,
    funcdef=None,
    cfg=None,
) -> Optional[IntegerRangeAnalysis]:
    if fn is None:
        fn = next((candidate for candidate in getattr(ast_ctx, "functions", ()) if candidate.name == function_name), None)
    if funcdef is None:
        funcdef = find_function_def(getattr(ast_ctx, "pycparser_ast", None), function_name)
    if fn is None or funcdef is None:
        return None
    if cfg is None:
        from ..analysis_session import analysis_session_for

        session = analysis_session_for(ast_ctx)
        cfg = session.analysis_cfg(function_name)
        if cfg is None:
            from .construction import clone_cached_structural_cfg

            cfg = clone_cached_structural_cfg(
                funcdef, line_map=getattr(ast_ctx, "line_map", None)
            )
    if not cfg.nodes or cfg.entry is None:
        return _SummaryAwareIntegerRangeAnalysis(ast_ctx, fn, cfg, {}, return_ranges)

    exposed = set(getattr(ast_ctx, "global_variables", {}))
    unstable_conditions = set(exposed)
    for name, variable in getattr(fn, "variables", {}).items():
        if getattr(variable, "is_volatile", False):
            unstable_conditions.add(str(name))
    for parameter in getattr(fn, "parameters", ()):
        if re.search(r"\bvolatile\b", getattr(parameter, "type_name", "")):
            unstable_conditions.add(str(parameter.name))
    for node in _descendants(funcdef):
        if type(node).__name__ == "UnaryOp" and node.op == "&" and _name(node.expr):
            exposed.add(_name(node.expr))
        if type(node).__name__ == "Decl" and getattr(node, "name", None) and "static" in (getattr(node, "storage", ()) or ()):
            unstable_conditions.add(str(node.name))

    incoming: Dict[int, Dict[str, IntegerRange]] = {
        cfg.entry: _seed_ranges(ast_ctx, fn, entry_ranges)
    }
    facts_before: Dict[int, Dict[str, IntegerRange]] = {}
    processed: Dict[int, int] = {}
    work = deque([cfg.entry])
    queued = set(work)
    while work:
        node_id = work.popleft()
        queued.remove(node_id)
        processed[node_id] = processed.get(node_id, 0) + 1
        state = incoming[node_id]
        facts_before[node_id] = dict(state)
        event = cfg.nodes[node_id]
        outgoing = _transfer(event, state, ast_ctx, fn, exposed, unstable_conditions)
        outgoing = _restore_direct_call_assignment(
            event,
            outgoing,
            ast_ctx,
            fn,
            exposed,
            unstable_conditions,
            return_ranges,
        )
        condition = _condition(event)
        proven_truth = (
            _condition_truth(condition, outgoing, ast_ctx, fn, unstable_conditions)
            if condition is not None
            else None
        )
        for index, successor in enumerate(event.successors):
            branch_truth = index == 0
            if condition is not None and index < 2 and proven_truth is not None and branch_truth != proven_truth:
                continue
            edge_state = dict(outgoing)
            if condition is not None and index < 2:
                constraints = _constraints(condition, branch_truth, ast_ctx, fn)
                if unstable_conditions:
                    constraints = {
                        name: interval
                        for name, interval in constraints.items()
                        if name not in unstable_conditions
                    }
                edge_state = _apply(edge_state, constraints, ast_ctx, fn)
            if edge_state is None:
                continue
            prior = incoming.get(successor)
            merged = edge_state if prior is None else _merge(prior, edge_state)
            if prior is not None and processed.get(successor, 0) >= 1:
                merged = {name: _widen(prior[name], merged[name]) for name in prior.keys() & merged.keys()}
            if prior != merged:
                incoming[successor] = merged
                if successor not in queued:
                    work.append(successor)
                    queued.add(successor)

    return _SummaryAwareIntegerRangeAnalysis(ast_ctx, fn, cfg, facts_before, return_ranges)


def _return_nodes(funcdef):
    from pycparser import c_ast

    result = []

    class Visitor(c_ast.NodeVisitor):
        def visit_Return(self, node):
            result.append(node)
            self.generic_visit(node)

    Visitor().visit(funcdef.body)
    return result


def _summarize_return(ast_ctx, fn, funcdef, analysis) -> Optional[IntegerRange]:
    destination = integer_type_range(fn.return_type, ast_ctx)
    if destination is None:
        return None
    returns = _return_nodes(funcdef)
    if not returns:
        return None
    summary: Optional[IntegerRange] = None
    for node in returns:
        expression = getattr(node, "expr", None)
        if expression is None:
            return None
        value = analysis.range_for_expression(expression, node)
        if value is None:
            return None
        converted = value if value.fits_within(destination) else destination
        summary = converted if summary is None else summary.hull(converted)
    return summary


def _summarize_parameters(
    ast_ctx,
    callee_name: str,
    callee_fn,
    callsites,
    caller_analyses,
) -> Dict[str, IntegerRange]:
    sites = callsites.get(callee_name, ())
    if not sites:
        return {}
    parameters = list(getattr(callee_fn, "parameters", ()))
    summaries: Dict[str, IntegerRange] = {}
    for index, parameter in enumerate(parameters):
        if parameter.is_pointer or parameter.is_array or integer_type_range(parameter.type_name, ast_ctx) is None:
            continue
        combined: Optional[IntegerRange] = None
        complete = True
        for caller_name, call in sites:
            arguments = getattr(getattr(call, "args", None), "exprs", None) or []
            if index >= len(arguments):
                complete = False
                break
            analysis = caller_analyses.get(caller_name)
            value = analysis.range_for_expression(arguments[index], call) if analysis is not None else None
            if value is None:
                complete = False
                break
            bound = _clamp_to_type(value, parameter.type_name, ast_ctx)
            if bound is None:
                complete = False
                break
            combined = bound if combined is None else combined.hull(bound)
        if complete and combined is not None:
            summaries[parameter.name] = combined
    return summaries


def _build_summary_index(ast_ctx) -> IntegerRangeSummaryIndex:
    models = _function_models(ast_ctx)
    funcdefs = _function_defs(ast_ctx)
    graph, callsites = _collect_calls(funcdefs)
    from ..analysis_session import analysis_session_for
    from .construction import clone_cached_structural_cfg

    session = analysis_session_for(ast_ctx)
    cfgs = {}
    for name, funcdef in funcdefs.items():
        cfg = session.analysis_cfg(name)
        if cfg is None:
            cfg = clone_cached_structural_cfg(
                funcdef, line_map=getattr(ast_ctx, "line_map", None)
            )
        cfgs[name] = cfg
    recursive = _recursive_functions(graph)
    escaped = _escaped_function_references(ast_ctx, funcdefs)
    eligible_parameters = {
        name
        for name, funcdef in funcdefs.items()
        if _private_static(funcdef) and name not in recursive and name not in escaped
    }

    parameter_ranges: Dict[str, Dict[str, IntegerRange]] = {}
    return_ranges: Dict[str, IntegerRange] = {}
    max_iterations = max(4, 2 * len(funcdefs) + 2)

    for iteration in range(1, max_iterations + 1):
        analyses = {
            name: _analyze_seeded(
                ast_ctx,
                name,
                parameter_ranges.get(name, {}),
                return_ranges,
                fn=models[name],
                funcdef=funcdefs[name],
                cfg=cfgs[name],
            )
            for name in funcdefs
        }
        next_returns: Dict[str, IntegerRange] = {}
        for name, funcdef in funcdefs.items():
            if name in recursive:
                continue
            analysis = analyses.get(name)
            fn = models.get(name)
            if analysis is None or fn is None:
                continue
            summary = _summarize_return(ast_ctx, fn, funcdef, analysis)
            if summary is not None:
                next_returns[name] = summary

        next_parameters: Dict[str, Dict[str, IntegerRange]] = {}
        for name in eligible_parameters:
            fn = models.get(name)
            if fn is None:
                continue
            summary = _summarize_parameters(ast_ctx, name, fn, callsites, analyses)
            if summary:
                next_parameters[name] = summary

        if next_parameters == parameter_ranges and next_returns == return_ranges:
            return IntegerRangeSummaryIndex(next_parameters, next_returns, analyses, True, iteration)
        parameter_ranges = next_parameters
        return_ranges = next_returns

    # If the bounded fixed point does not converge, expose no behavioral facts.
    return IntegerRangeSummaryIndex({}, {}, {}, False, max_iterations)


def integer_range_summary_index(ast_ctx) -> IntegerRangeSummaryIndex:
    """Return the summary index owned by this parsed/configured AST context."""

    attribute = "_cgull_integer_range_summary_index"
    cached = getattr(ast_ctx, attribute, None)
    if isinstance(cached, IntegerRangeSummaryIndex):
        return cached
    summary = _build_summary_index(ast_ctx)
    setattr(ast_ctx, attribute, summary)
    return summary


def analyze_integer_ranges(ast_ctx, function_name: str) -> Optional[IntegerRangeAnalysis]:
    """Analyze one function with conservative same-TU direct-helper summaries."""

    summaries = integer_range_summary_index(ast_ctx)
    analysis = summaries.analyses.get(function_name)
    if analysis is not None:
        return analysis
    # Non-convergence drops only interprocedural behavioral summaries; retain
    # the ordinary intraprocedural CFG range analysis for conservative parity.
    return _analyze_seeded(ast_ctx, function_name, {}, {})
