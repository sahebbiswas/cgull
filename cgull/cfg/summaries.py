"""Interprocedural function summaries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, FrozenSet, Mapping, Optional, Set, Tuple

from ..ast_analyzer import _format_pycparser_expr
from .call_graph import build_translation_unit_call_graph
from .construction import _guarded_expression_uses, _is_nullish, build_cfg, find_function_def
from .dataflow import meet_nullness
from .fixed_point import FiniteLattice, FixedPointConfig, FixedPointDiagnostic, SCCFixedPointEngine
from .model import Allocation, FunctionSummary, Nullness


def _unwrap_cast(node):
    while node is not None and type(node).__name__ in {"Cast", "ExprList"}:
        if type(node).__name__ == "Cast":
            node = node.expr
        else:
            node = node.exprs[-1] if getattr(node, "exprs", None) else None
    return node


def _get_builtin_summaries(
    alloc_funcs: Optional[Set[str]] = None,
    dealloc_funcs: Optional[Set[str]] = None,
    realloc_funcs: Optional[Set[str]] = None,
) -> Dict[str, FunctionSummary]:
    alloc_set = set(alloc_funcs) if alloc_funcs is not None else {
        "malloc", "calloc", "realloc", "aligned_alloc", "strdup", "strndup",
        "valloc", "pvalloc", "memalign",
    }
    dealloc_set = set(dealloc_funcs) if dealloc_funcs is not None else {"free", "cfree", "vfree"}
    if realloc_funcs:
        alloc_set.update(realloc_funcs)

    builtins: Dict[str, FunctionSummary] = {}
    for f in sorted(dealloc_set):
        builtins[f] = FunctionSummary(
            freed_params={0}, return_nullness=Nullness.UNKNOWN, returns_allocation=False
        )
    for f in sorted(alloc_set):
        builtins[f] = FunctionSummary(
            freed_params=set(), return_nullness=Nullness.MAYBE_NULL, returns_allocation=True
        )
    return builtins


@dataclass(frozen=True)
class _SummaryFact:
    """Internal summary product with a real fixed-point bottom value."""

    freed_params: FrozenSet[int] = frozenset()
    unsafe_deref_params: FrozenSet[int] = frozenset()
    return_nullness: Optional[Nullness] = None  # None is BOTTOM, never exposed to callers.
    returns_allocation: bool = False
    is_unknown: bool = False


class _FunctionSummaryLattice(FiniteLattice[_SummaryFact]):
    def __init__(self, parameter_counts: Mapping[str, int]) -> None:
        self._parameter_counts = dict(parameter_counts)
        # Each parameter can enter two may-effect sets, allocation can rise once,
        # and return nullness has a short finite chain.  This is a conservative
        # finite upper bound used to make the domain contract executable.
        max_params = max(self._parameter_counts.values(), default=0)
        self.max_height = max(4, (2 * max_params) + 5)

    def bottom(self, symbol: str) -> _SummaryFact:
        return _SummaryFact()

    def join(self, left: _SummaryFact, right: _SummaryFact) -> _SummaryFact:
        return _SummaryFact(
            freed_params=left.freed_params | right.freed_params,
            unsafe_deref_params=left.unsafe_deref_params | right.unsafe_deref_params,
            return_nullness=_join_summary_nullness(left.return_nullness, right.return_nullness),
            returns_allocation=left.returns_allocation or right.returns_allocation,
            is_unknown=left.is_unknown or right.is_unknown,
        )

    def unknown(self, symbol: str, current: _SummaryFact) -> _SummaryFact:
        # Unknown effects are represented conservatively as all parameters
        # possibly affected.  Existing consumers that do not yet inspect
        # ``is_unknown`` therefore cannot accidentally treat a limit as safe.
        all_params = frozenset(range(self._parameter_counts.get(symbol, 0)))
        return _SummaryFact(
            freed_params=current.freed_params | all_params,
            unsafe_deref_params=current.unsafe_deref_params | all_params,
            return_nullness=Nullness.UNKNOWN,
            returns_allocation=True,
            is_unknown=True,
        )


def _join_summary_nullness(left: Optional[Nullness], right: Optional[Nullness]) -> Optional[Nullness]:
    """Join summary nullness with distinct BOTTOM and UNKNOWN/top values."""
    if left is None:
        return right
    if right is None:
        return left
    if left == Nullness.UNKNOWN or right == Nullness.UNKNOWN:
        return Nullness.UNKNOWN
    if left == right:
        return left
    if left == Nullness.MAYBE_NULL or right == Nullness.MAYBE_NULL:
        return Nullness.MAYBE_NULL
    return Nullness.MAYBE_NULL


def _fact_to_summary(fact: _SummaryFact) -> FunctionSummary:
    return FunctionSummary(
        freed_params=set(fact.freed_params),
        unsafe_deref_params=set(fact.unsafe_deref_params),
        return_nullness=fact.return_nullness if fact.return_nullness is not None else Nullness.UNKNOWN,
        returns_allocation=fact.returns_allocation,
        is_unknown=fact.is_unknown,
    )


def _current_summaries(
    builtins: Mapping[str, FunctionSummary], facts: Mapping[str, _SummaryFact]
) -> Dict[str, FunctionSummary]:
    result = dict(builtins)
    for name, fact in facts.items():
        result[name] = _fact_to_summary(fact)
    return result


def _analyze_one_function(
    ast_ctx,
    fn,
    summaries: Mapping[str, FunctionSummary],
    alloc_funcs: Optional[Set[str]],
    dealloc_funcs: Optional[Set[str]],
    realloc_funcs: Optional[Set[str]],
) -> _SummaryFact:
    name = fn.name
    param_names = [p.name for p in fn.parameters if p.name]
    cfg = None
    if getattr(ast_ctx, "has_pycparser", False) and ast_ctx.pycparser_ast is not None:
        funcdef = find_function_def(ast_ctx.pycparser_ast, name)
        if funcdef is not None:
            cfg = build_cfg(
                funcdef,
                alloc_funcs=alloc_funcs,
                dealloc_funcs=dealloc_funcs,
                realloc_funcs=realloc_funcs,
                summaries=summaries,
                line_map=getattr(ast_ctx, "line_map", None),
            )

    freed_params: Set[int] = set()
    unsafe_deref_params: Set[int] = set()
    return_nullness_set: Set[Nullness] = set()
    returns_alloc = False

    if cfg is not None:
        initial_initialized = (
            {p.name for p in fn.parameters if p.name}
            | set(getattr(ast_ctx, "global_variables", {}).keys())
            | {
                var.name
                for var in fn.variables.values()
                if getattr(var, "has_initializer", False) and var.name
            }
        )
        cfg.analyze_dataflow(initial_nonnull=set(), initial_initialized=initial_initialized)

        for i, p_name in enumerate(param_names):
            for node in cfg.nodes.values():
                if p_name in node.freed:
                    freed_params.add(i)
                    break

        # Track unsafe dereferences against each parameter's incoming location,
        # preserving the pre-engine alias semantics.
        for i, p_name in enumerate(param_names):
            param_location = f"var_{p_name}"
            for node in cfg.nodes.values():
                loc_map = cfg.get_loc_map_at_node(node.node_id)
                for use_kind, payload, guarded_nonnull in _guarded_expression_uses(
                    getattr(node, "_ast_node", None)
                ):
                    if use_kind == "deref":
                        deref_var = payload
                        if (
                            param_location in loc_map.get(deref_var, set())
                            and deref_var not in guarded_nonnull
                            and cfg.query_nullness(deref_var, node.node_id) != Nullness.NON_NULL
                        ):
                            unsafe_deref_params.add(i)
                            break
                        continue

                    callee = _format_pycparser_expr(payload.name)
                    callee_summary = summaries.get(callee)
                    args = list(getattr(payload.args, "exprs", []) or []) if payload.args else []
                    if not callee_summary:
                        continue
                    for arg_index in callee_summary.unsafe_deref_params:
                        if arg_index >= len(args):
                            continue
                        arg = _unwrap_cast(args[arg_index])
                        if type(arg).__name__ != "ID":
                            continue
                        arg_name = str(arg.name)
                        if (
                            param_location in loc_map.get(arg_name, set())
                            and arg_name not in guarded_nonnull
                            and cfg.query_nullness(arg_name, node.node_id) != Nullness.NON_NULL
                        ):
                            unsafe_deref_params.add(i)
                            break
                    if i in unsafe_deref_params:
                        break
                if i in unsafe_deref_params:
                    break

        for node in cfg.nodes.values():
            if node.kind != "return":
                continue
            ret_expr = node.expr_str.strip()
            ret_ast = getattr(node, "_ast_node", None)
            expr_ast = getattr(ret_ast, "expr", None) if ret_ast is not None else None

            ret_nullness = Nullness.UNKNOWN
            if ret_expr in param_names:
                ret_nullness = cfg.query_nullness(ret_expr, node.node_id)
            elif ret_expr in fn.variables:
                ret_nullness = cfg.query_nullness(ret_expr, node.node_id)
                if cfg.query_allocation(ret_expr, node.node_id) in (
                    Allocation.ALLOCATED,
                    Allocation.MAYBE_ALLOCATED,
                ):
                    returns_alloc = True
                    if ret_nullness == Nullness.UNKNOWN:
                        ret_nullness = Nullness.MAYBE_NULL
            elif expr_ast is not None and type(expr_ast).__name__ == "FuncCall":
                callee = _format_pycparser_expr(expr_ast.name)
                callee_summary = summaries.get(callee)
                if callee_summary:
                    ret_nullness = callee_summary.return_nullness
                    if callee_summary.returns_allocation:
                        returns_alloc = True
            elif expr_ast is not None and _is_nullish(expr_ast):
                ret_nullness = Nullness.NULL
            elif ret_expr in {"NULL", "nullptr", "0", "0x0", "(void*)0", "(void *)0"}:
                ret_nullness = Nullness.NULL

            return_nullness_set.add(ret_nullness)

    # Preserve the existing intra-function path merge semantics.  BOTTOM is an
    # interprocedural engine concern; legacy meet_nullness remains the behavior
    # for multiple concrete return statements.
    if not return_nullness_set:
        final_ret_nullness = Nullness.UNKNOWN
    else:
        final_ret_nullness = None
        for rn in sorted(return_nullness_set, key=lambda item: item.value):
            final_ret_nullness = rn if final_ret_nullness is None else meet_nullness(final_ret_nullness, rn)

    return _SummaryFact(
        freed_params=frozenset(freed_params),
        unsafe_deref_params=frozenset(unsafe_deref_params),
        return_nullness=final_ret_nullness or Nullness.UNKNOWN,
        returns_allocation=returns_alloc,
        is_unknown=False,
    )


@dataclass(frozen=True)
class FunctionSummaryAnalysisResult:
    summaries: Mapping[str, FunctionSummary]
    diagnostics: Tuple[FixedPointDiagnostic, ...] = ()
    iterations_by_scc: Mapping[Tuple[str, ...], int] = None

    def __post_init__(self) -> None:
        if self.iterations_by_scc is None:
            object.__setattr__(self, "iterations_by_scc", {})


def analyze_function_summaries_detailed(
    ast_ctx,
    alloc_funcs: Optional[Set[str]] = None,
    dealloc_funcs: Optional[Set[str]] = None,
    realloc_funcs: Optional[Set[str]] = None,
    *,
    fixed_point_config: Optional[FixedPointConfig] = None,
    call_graph=None,
) -> FunctionSummaryAnalysisResult:
    """Compute summaries with SCC convergence diagnostics and explicit limits."""
    builtins = _get_builtin_summaries(
        alloc_funcs=alloc_funcs,
        dealloc_funcs=dealloc_funcs,
        realloc_funcs=realloc_funcs,
    )
    functions = [fn for fn in getattr(ast_ctx, "functions", ()) if getattr(fn, "name", None)]
    fn_map = {fn.name: fn for fn in functions}
    if not fn_map:
        return FunctionSummaryAnalysisResult(dict(sorted(builtins.items())))

    if not getattr(ast_ctx, "has_pycparser", False) or ast_ctx.pycparser_ast is None:
        summaries = dict(builtins)
        summaries.update({name: FunctionSummary() for name in sorted(fn_map)})
        return FunctionSummaryAnalysisResult(dict(sorted(summaries.items())))

    graph = call_graph or build_translation_unit_call_graph(ast_ctx)
    parameter_counts = {
        name: len([p for p in fn.parameters if p.name])
        for name, fn in fn_map.items()
    }
    lattice = _FunctionSummaryLattice(parameter_counts)
    engine = SCCFixedPointEngine(graph, lattice, fixed_point_config)

    def transfer(name, facts, _config):
        fn = fn_map[name]
        summaries = _current_summaries(builtins, facts)
        return _analyze_one_function(
            ast_ctx,
            fn,
            summaries,
            alloc_funcs,
            dealloc_funcs,
            realloc_funcs,
        )

    result = engine.run(transfer)
    summaries = dict(builtins)
    for name in sorted(fn_map):
        fact = result.facts.get(name, lattice.bottom(name))
        summaries[name] = _fact_to_summary(fact)
    return FunctionSummaryAnalysisResult(
        summaries=dict(sorted(summaries.items())),
        diagnostics=result.diagnostics,
        iterations_by_scc=result.iterations_by_scc,
    )


def analyze_function_summaries(
    ast_ctx,
    alloc_funcs: Optional[Set[str]] = None,
    dealloc_funcs: Optional[Set[str]] = None,
    realloc_funcs: Optional[Set[str]] = None,
) -> Dict[str, FunctionSummary]:
    """Compatibility wrapper returning the historic ``dict`` result."""
    return dict(
        analyze_function_summaries_detailed(
            ast_ctx,
            alloc_funcs=alloc_funcs,
            dealloc_funcs=dealloc_funcs,
            realloc_funcs=realloc_funcs,
        ).summaries
    )


def serialize_function_summaries(summaries: Mapping[str, FunctionSummary]) -> bytes:
    """Canonical, byte-for-byte deterministic summary serialization."""
    payload = {
        name: {
            "freed_params": sorted(summary.freed_params),
            "unsafe_deref_params": sorted(summary.unsafe_deref_params),
            "return_nullness": summary.return_nullness.value,
            "returns_allocation": bool(summary.returns_allocation),
            "is_unknown": bool(summary.is_unknown),
        }
        for name, summary in sorted(summaries.items())
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
