"""Interprocedural allocation ownership, escape, and free effects.

This domain is intentionally separate from rule policy.  It summarizes how a
callee changes ownership of pointer arguments and exposes per-call effects that
memory lifecycle rules can query without rediscovering calls from source text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, Mapping, Optional, Set, Tuple

from ..call_effects import BUILTIN_CALL_EFFECTS, CallEffectRegistry, ReturnEffect
from .call_graph import build_translation_unit_call_graph
from .construction import build_cfg, find_function_def
from .fixed_point import FiniteLattice, FixedPointConfig, FixedPointDiagnostic, SCCFixedPointEngine
from .summaries import analyze_function_summaries


__all__ = [
    "NodeOwnershipEffects",
    "OwnershipSummary",
    "OwnershipSummaryAnalysisResult",
    "analyze_ownership_summaries",
    "analyze_ownership_summaries_detailed",
    "ownership_effects_for_cfg",
]


_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")


@dataclass(frozen=True)
class OwnershipSummary:
    """Caller-visible ownership effects for one function.

    Definite sets apply on every reachable function exit. ``maybe_*`` sets
    contain effects that occur on at least one but not every exit.  A returned
    alias identifies parameters whose incoming location may be returned.
    """

    freed_params: FrozenSet[int] = frozenset()
    maybe_freed_params: FrozenSet[int] = frozenset()
    transferred_params: FrozenSet[int] = frozenset()
    maybe_transferred_params: FrozenSet[int] = frozenset()
    escaped_params: FrozenSet[int] = frozenset()
    maybe_escaped_params: FrozenSet[int] = frozenset()
    consumed_params: FrozenSet[int] = frozenset()
    maybe_consumed_params: FrozenSet[int] = frozenset()
    returned_alias_params: FrozenSet[int] = frozenset()
    returns_allocation: bool = False
    is_unknown: bool = False


@dataclass(frozen=True)
class NodeOwnershipEffects:
    """Ownership effects of calls contained in a single CFG event."""

    freed: FrozenSet[str] = frozenset()
    maybe_freed: FrozenSet[str] = frozenset()
    transferred: FrozenSet[str] = frozenset()
    maybe_transferred: FrozenSet[str] = frozenset()
    escaped: FrozenSet[str] = frozenset()
    maybe_escaped: FrozenSet[str] = frozenset()
    unknown_escaped: FrozenSet[str] = frozenset()
    allocation_results: FrozenSet[str] = frozenset()
    returned_aliases: Tuple[Tuple[str, str], ...] = ()

    @property
    def consumed(self) -> FrozenSet[str]:
        return self.freed | self.transferred | self.escaped

    @property
    def maybe_consumed(self) -> FrozenSet[str]:
        return self.maybe_freed | self.maybe_transferred | self.maybe_escaped


@dataclass(frozen=True)
class OwnershipSummaryAnalysisResult:
    summaries: Mapping[str, OwnershipSummary]
    diagnostics: Tuple[FixedPointDiagnostic, ...] = ()
    iterations_by_scc: Mapping[Tuple[str, ...], int] = None

    def __post_init__(self) -> None:
        if self.iterations_by_scc is None:
            object.__setattr__(self, "iterations_by_scc", {})


@dataclass(frozen=True)
class _OwnershipFact:
    initialized: bool = False
    freed: FrozenSet[int] = frozenset()
    may_freed: FrozenSet[int] = frozenset()
    transferred: FrozenSet[int] = frozenset()
    may_transferred: FrozenSet[int] = frozenset()
    escaped: FrozenSet[int] = frozenset()
    may_escaped: FrozenSet[int] = frozenset()
    consumed: FrozenSet[int] = frozenset()
    may_consumed: FrozenSet[int] = frozenset()
    returned_aliases: FrozenSet[int] = frozenset()
    returns_allocation: bool = False
    is_unknown: bool = False


class _OwnershipLattice(FiniteLattice[_OwnershipFact]):
    def __init__(self, parameter_counts: Mapping[str, int]) -> None:
        self._parameter_counts = dict(parameter_counts)
        max_params = max(parameter_counts.values(), default=0)
        self.max_height = max(4, (10 * max_params) + 4)

    def bottom(self, symbol: str) -> _OwnershipFact:
        return _OwnershipFact()

    def join(self, left: _OwnershipFact, right: _OwnershipFact) -> _OwnershipFact:
        if not left.initialized:
            return right
        if not right.initialized:
            return left
        return _OwnershipFact(
            initialized=True,
            freed=left.freed & right.freed,
            may_freed=left.may_freed | right.may_freed | left.freed | right.freed,
            transferred=left.transferred & right.transferred,
            may_transferred=(
                left.may_transferred | right.may_transferred | left.transferred | right.transferred
            ),
            escaped=left.escaped & right.escaped,
            may_escaped=left.may_escaped | right.may_escaped | left.escaped | right.escaped,
            consumed=left.consumed & right.consumed,
            may_consumed=left.may_consumed | right.may_consumed | left.consumed | right.consumed,
            returned_aliases=left.returned_aliases | right.returned_aliases,
            returns_allocation=left.returns_allocation or right.returns_allocation,
            is_unknown=left.is_unknown or right.is_unknown,
        )

    def unknown(self, symbol: str, current: _OwnershipFact) -> _OwnershipFact:
        all_params = frozenset(range(self._parameter_counts.get(symbol, 0)))
        return _OwnershipFact(
            initialized=True,
            may_freed=current.may_freed | current.freed | all_params,
            may_transferred=current.may_transferred | current.transferred,
            may_escaped=current.may_escaped | current.escaped | all_params,
            may_consumed=current.may_consumed | current.consumed | all_params,
            returned_aliases=current.returned_aliases | all_params,
            returns_allocation=True,
            is_unknown=True,
        )


def _summary_from_fact(fact: _OwnershipFact) -> OwnershipSummary:
    freed = fact.freed
    transferred = fact.transferred
    escaped = fact.escaped
    consumed = fact.consumed
    return OwnershipSummary(
        freed_params=freed,
        maybe_freed_params=(fact.may_freed - freed),
        transferred_params=transferred,
        maybe_transferred_params=(fact.may_transferred - transferred),
        escaped_params=escaped,
        maybe_escaped_params=(fact.may_escaped - escaped),
        consumed_params=consumed,
        maybe_consumed_params=(fact.may_consumed - consumed),
        returned_alias_params=fact.returned_aliases,
        returns_allocation=fact.returns_allocation,
        is_unknown=fact.is_unknown,
    )


def _current_summaries(facts: Mapping[str, _OwnershipFact]) -> Dict[str, OwnershipSummary]:
    return {
        name: _summary_from_fact(fact)
        for name, fact in facts.items()
        if fact.initialized
    }


def _actual_var(expression: str) -> Optional[str]:
    text = expression.strip()
    if _IDENTIFIER.fullmatch(text):
        return text
    identifiers = re.findall(r"[A-Za-z_]\w*", text)
    if not identifiers:
        return None
    candidate = identifiers[-1]
    if candidate in {"NULL", "nullptr", "void", "const", "volatile", "unsigned", "signed"}:
        return None
    return candidate


def _vars_for_indexes(actual_arguments: Tuple[str, ...], indexes) -> Set[str]:
    result: Set[str] = set()
    for index in indexes:
        if index >= len(actual_arguments):
            continue
        var = _actual_var(actual_arguments[index])
        if var:
            result.add(var)
    return result


def _is_reallocation_model(model) -> bool:
    return bool(
        model
        and model.return_effect is ReturnEffect.ALLOCATION
        and model.deallocates
    )


def ownership_effects_for_cfg(
    cfg,
    summaries: Mapping[str, OwnershipSummary],
    *,
    call_effects: Optional[CallEffectRegistry] = None,
) -> Dict[int, NodeOwnershipEffects]:
    """Return deterministic caller-visible effects for every CFG node."""
    registry = call_effects or BUILTIN_CALL_EFFECTS
    result: Dict[int, NodeOwnershipEffects] = {}

    for node_id, node in cfg.nodes.items():
        freed: Set[str] = set()
        maybe_freed: Set[str] = set()
        transferred: Set[str] = set()
        maybe_transferred: Set[str] = set()
        escaped: Set[str] = set()
        maybe_escaped: Set[str] = set()
        unknown_escaped: Set[str] = set()
        allocation_results: Set[str] = set()
        returned_aliases: Set[Tuple[str, str]] = set()

        for call in node.calls:
            callee = call.direct_callee
            model = registry.for_function(callee)
            summary = summaries.get(callee) if callee else None

            if model is not None:
                # realloc-like calls only release the old storage on successful
                # replacement. The CFG already tracks that result correlation,
                # so do not flatten it into an unconditional call-site free.
                if not _is_reallocation_model(model):
                    freed.update(_vars_for_indexes(call.actual_arguments, model.deallocates))
                transferred.update(_vars_for_indexes(call.actual_arguments, model.takes_ownership))
                escaped.update(_vars_for_indexes(call.actual_arguments, model.escapes))
                if model.return_effect is ReturnEffect.ALLOCATION and call.result_target:
                    allocation_results.add(call.result_target)

            if summary is not None:
                freed.update(_vars_for_indexes(call.actual_arguments, summary.freed_params))
                maybe_freed.update(_vars_for_indexes(call.actual_arguments, summary.maybe_freed_params))
                transferred.update(_vars_for_indexes(call.actual_arguments, summary.transferred_params))
                maybe_transferred.update(
                    _vars_for_indexes(call.actual_arguments, summary.maybe_transferred_params)
                )
                escaped.update(_vars_for_indexes(call.actual_arguments, summary.escaped_params))
                maybe_escaped.update(_vars_for_indexes(call.actual_arguments, summary.maybe_escaped_params))
                if summary.returns_allocation and call.result_target:
                    allocation_results.add(call.result_target)
                if call.result_target:
                    for index in summary.returned_alias_params:
                        if index >= len(call.actual_arguments):
                            continue
                        source = _actual_var(call.actual_arguments[index])
                        if source:
                            returned_aliases.add((call.result_target, source))

            if model is None and summary is None:
                for expression in call.actual_arguments:
                    var = _actual_var(expression)
                    if var:
                        unknown_escaped.add(var)
                        maybe_escaped.add(var)

        result[node_id] = NodeOwnershipEffects(
            freed=frozenset(freed),
            maybe_freed=frozenset(maybe_freed - freed),
            transferred=frozenset(transferred),
            maybe_transferred=frozenset(maybe_transferred - transferred),
            escaped=frozenset(escaped),
            maybe_escaped=frozenset(maybe_escaped - escaped),
            unknown_escaped=frozenset(unknown_escaped),
            allocation_results=frozenset(allocation_results),
            returned_aliases=tuple(sorted(returned_aliases)),
        )
    return result


def _reachable_and_predecessors(cfg):
    if cfg.entry is None or cfg.entry not in cfg.nodes:
        return set(), {}
    reachable: Set[int] = set()
    queue = [cfg.entry]
    while queue:
        node_id = queue.pop(0)
        if node_id in reachable or node_id not in cfg.nodes:
            continue
        reachable.add(node_id)
        queue.extend(cfg.nodes[node_id].successors)
    predecessors = {node_id: set() for node_id in reachable}
    for node_id in reachable:
        for successor in cfg.nodes[node_id].successors:
            if successor in reachable:
                predecessors[successor].add(node_id)
    return reachable, predecessors


def _path_sets(cfg, node_must: Mapping[int, Set[int]], node_may: Mapping[int, Set[int]]):
    reachable, predecessors = _reachable_and_predecessors(cfg)
    if not reachable:
        return set(), set()

    must_in = {node_id: set() for node_id in reachable}
    may_in = {node_id: set() for node_id in reachable}
    must_out = {node_id: set() for node_id in reachable}
    may_out = {node_id: set() for node_id in reachable}

    changed = True
    while changed:
        changed = False
        for node_id in sorted(reachable):
            preds = predecessors[node_id]
            if node_id == cfg.entry or not preds:
                in_must: Set[int] = set()
                in_may: Set[int] = set()
            else:
                ordered = sorted(preds)
                in_must = set(must_out[ordered[0]])
                for pred in ordered[1:]:
                    in_must.intersection_update(must_out[pred])
                in_may = set().union(*(may_out[pred] for pred in ordered))
            new_must = in_must | node_must.get(node_id, set())
            new_may = in_may | node_must.get(node_id, set()) | node_may.get(node_id, set())
            if (
                in_must != must_in[node_id]
                or in_may != may_in[node_id]
                or new_must != must_out[node_id]
                or new_may != may_out[node_id]
            ):
                must_in[node_id] = in_must
                may_in[node_id] = in_may
                must_out[node_id] = new_must
                may_out[node_id] = new_may
                changed = True

    exits = []
    for node_id in sorted(reachable):
        successors = [s for s in cfg.nodes[node_id].successors if s in reachable]
        if not successors:
            exits.append((must_out[node_id], may_out[node_id]))
        elif cfg.nodes[node_id].kind.endswith("_cond") and len(successors) < 2:
            exits.append((must_in[node_id], may_in[node_id] | node_may.get(node_id, set())))

    if not exits:
        return set(), set().union(*(may_out.values()))
    definite = set(exits[0][0])
    for exit_must, _ in exits[1:]:
        definite.intersection_update(exit_must)
    possible = set().union(*(exit_may for _, exit_may in exits))
    return definite, possible


def _param_indexes_for_vars(cfg, node_id: int, variables: Set[str], param_names: Tuple[str, ...]) -> Set[int]:
    loc_map = cfg.get_loc_map_at_node(node_id)
    result: Set[int] = set()
    for var in variables:
        locations = loc_map.get(var, {f"var_{var}"})
        for index, param_name in enumerate(param_names):
            if f"var_{param_name}" in locations:
                result.add(index)
    return result


def _analyze_one_function(
    ast_ctx,
    fn,
    ownership_summaries: Mapping[str, OwnershipSummary],
    function_summaries,
    call_effects: CallEffectRegistry,
) -> _OwnershipFact:
    param_names = tuple(p.name for p in fn.parameters if p.name)
    funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
    if funcdef is None:
        return _OwnershipFact(initialized=True)

    cfg = build_cfg(funcdef, summaries=function_summaries, line_map=getattr(ast_ctx, "line_map", None))
    initial_initialized = (
        set(param_names)
        | set(getattr(ast_ctx, "global_variables", {}).keys())
        | {
            var.name
            for var in fn.variables.values()
            if getattr(var, "has_initializer", False) and var.name
        }
    )
    cfg.analyze_dataflow(initial_nonnull=set(), initial_initialized=initial_initialized)
    node_effects = ownership_effects_for_cfg(cfg, ownership_summaries, call_effects=call_effects)

    categories = {
        "freed": ({}, {}),
        "transferred": ({}, {}),
        "escaped": ({}, {}),
        "consumed": ({}, {}),
    }
    for node_id, effects in node_effects.items():
        free_must = _param_indexes_for_vars(cfg, node_id, set(effects.freed), param_names)
        free_may_vars = set(effects.maybe_freed)
        free_may_vars.update(getattr(cfg.nodes[node_id], "realloc_inputs", set()))
        # Return expressions do not currently populate realloc_inputs in CFG
        # construction, so derive realloc-like inputs from structured calls as
        # well. This stays summary-only and does not flatten direct CFG state.
        for call in cfg.nodes[node_id].calls:
            model = call_effects.for_function(call.direct_callee)
            if _is_reallocation_model(model):
                free_may_vars.update(
                    _vars_for_indexes(call.actual_arguments, model.deallocates)
                )
        free_may = _param_indexes_for_vars(cfg, node_id, free_may_vars, param_names)
        transfer_must = _param_indexes_for_vars(cfg, node_id, set(effects.transferred), param_names)
        transfer_may = _param_indexes_for_vars(cfg, node_id, set(effects.maybe_transferred), param_names)
        escape_must = _param_indexes_for_vars(cfg, node_id, set(effects.escaped), param_names)
        escape_may = _param_indexes_for_vars(
            cfg, node_id, set(effects.maybe_escaped | effects.unknown_escaped), param_names
        )
        categories["freed"][0][node_id] = free_must
        categories["freed"][1][node_id] = free_may
        categories["transferred"][0][node_id] = transfer_must
        categories["transferred"][1][node_id] = transfer_may
        categories["escaped"][0][node_id] = escape_must
        categories["escaped"][1][node_id] = escape_may
        categories["consumed"][0][node_id] = free_must | transfer_must | escape_must
        categories["consumed"][1][node_id] = free_may | transfer_may | escape_may

    free_def, free_possible = _path_sets(cfg, *categories["freed"])
    transfer_def, transfer_possible = _path_sets(cfg, *categories["transferred"])
    escape_def, escape_possible = _path_sets(cfg, *categories["escaped"])
    consumed_def, consumed_possible = _path_sets(cfg, *categories["consumed"])

    returned_aliases: Set[int] = set()
    for node_id, node in cfg.nodes.items():
        if node.kind != "return":
            continue
        var = _actual_var(node.expr_str)
        if var:
            returned_aliases.update(_param_indexes_for_vars(cfg, node_id, {var}, param_names))
        for target, source in node_effects[node_id].returned_aliases:
            if target == "return":
                returned_aliases.update(_param_indexes_for_vars(cfg, node_id, {source}, param_names))

    function_summary = function_summaries.get(fn.name)
    return _OwnershipFact(
        initialized=True,
        freed=frozenset(free_def),
        may_freed=frozenset(free_possible),
        transferred=frozenset(transfer_def),
        may_transferred=frozenset(transfer_possible),
        escaped=frozenset(escape_def),
        may_escaped=frozenset(escape_possible),
        consumed=frozenset(consumed_def),
        may_consumed=frozenset(consumed_possible),
        returned_aliases=frozenset(returned_aliases),
        returns_allocation=bool(function_summary and function_summary.returns_allocation),
    )


def analyze_ownership_summaries_detailed(
    ast_ctx,
    *,
    call_effects: Optional[CallEffectRegistry] = None,
    fixed_point_config: Optional[FixedPointConfig] = None,
    call_graph=None,
) -> OwnershipSummaryAnalysisResult:
    """Compute ownership summaries using the shared SCC fixed-point engine."""
    functions = [fn for fn in getattr(ast_ctx, "functions", ()) if getattr(fn, "name", None)]
    fn_map = {fn.name: fn for fn in functions}
    if not fn_map or not getattr(ast_ctx, "has_pycparser", False) or ast_ctx.pycparser_ast is None:
        return OwnershipSummaryAnalysisResult({})

    registry = call_effects or BUILTIN_CALL_EFFECTS
    function_summaries = analyze_function_summaries(ast_ctx, call_effects=registry)
    graph = call_graph or build_translation_unit_call_graph(ast_ctx)
    parameter_counts = {
        name: len([p for p in fn.parameters if p.name])
        for name, fn in fn_map.items()
    }
    lattice = _OwnershipLattice(parameter_counts)
    engine = SCCFixedPointEngine(graph, lattice, fixed_point_config)

    def transfer(name, facts, _config):
        return _analyze_one_function(
            ast_ctx,
            fn_map[name],
            _current_summaries(facts),
            function_summaries,
            registry,
        )

    result = engine.run(transfer)
    summaries = {
        name: _summary_from_fact(result.facts.get(name, lattice.bottom(name)))
        for name in sorted(fn_map)
    }
    return OwnershipSummaryAnalysisResult(
        summaries=summaries,
        diagnostics=result.diagnostics,
        iterations_by_scc=result.iterations_by_scc,
    )


def analyze_ownership_summaries(
    ast_ctx,
    *,
    call_effects: Optional[CallEffectRegistry] = None,
    call_graph=None,
) -> Dict[str, OwnershipSummary]:
    return dict(
        analyze_ownership_summaries_detailed(
            ast_ctx,
            call_effects=call_effects,
            call_graph=call_graph,
        ).summaries
    )
