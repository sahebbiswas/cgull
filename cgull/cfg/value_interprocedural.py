"""Whole-TU actual-to-formal propagation for interprocedural value facts."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Mapping, Optional, Tuple

from pycparser import c_parser

from ..semantic_models import EMPTY_SEMANTIC_MODELS, SemanticModelRegistry
from .call_graph import build_translation_unit_call_graph
from .construction import build_cfg, find_function_def
from .fixed_point import FixedPointConfig, FixedPointDiagnostic
from .value_facts import (
    ValueDataflowResult,
    ValueFact,
    ValueFunctionSummary,
    ValueSummaryAnalysisResult,
    _canonical_location,
    _expression_fact,
    _join_facts,
    _merge_state,
    _transfer_event,
    analyze_value_summaries_detailed,
)


_ACTUAL_PARSER = c_parser.CParser()


@dataclass(frozen=True)
class TranslationUnitValueResult:
    summaries: Mapping[str, ValueFunctionSummary]
    parameter_facts: Mapping[str, Tuple[ValueFact, ...]]
    function_results: Mapping[str, ValueDataflowResult]
    diagnostics: Tuple[FixedPointDiagnostic, ...] = ()

    def function(self, name: str) -> Optional[ValueDataflowResult]:
        return self.function_results.get(name)


def analyze_translation_unit_value_dataflow(
    ast_ctx,
    semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS,
    *,
    fixed_point_config: Optional[FixedPointConfig] = None,
    call_graph=None,
) -> TranslationUnitValueResult:
    """Propagate caller actuals to formals in deterministic caller-first SCC order.

    Return facts are evaluated with the context-independent summary transfer in
    :mod:`value_facts`.  Parameter facts are then joined across all direct
    callers.  Recursive SCCs iterate until stable; unresolved external entry
    parameters remain ``UNKNOWN`` rather than being inferred safe.
    """
    config = fixed_point_config or FixedPointConfig()
    graph = call_graph or build_translation_unit_call_graph(ast_ctx)
    summary_result: ValueSummaryAnalysisResult = analyze_value_summaries_detailed(
        ast_ctx,
        semantic_models,
        fixed_point_config=config,
        call_graph=graph,
    )
    fn_meta = {
        fn.name: fn
        for fn in getattr(ast_ctx, "functions", ())
        if getattr(fn, "name", None)
    }
    parameter_names = {
        name: tuple(p.name for p in fn.parameters if p.name)
        for name, fn in fn_meta.items()
    }

    # None is the internal BOTTOM for a parameter that has not yet received a
    # reachable caller contribution.  Public results materialize it as UNKNOWN.
    incoming: Dict[str, list] = {
        name: [None] * len(parameter_names.get(name, ())) for name in fn_meta
    }
    results: Dict[str, ValueDataflowResult] = {}
    diagnostics = list(summary_result.diagnostics)

    # Public/external entry functions may be called outside the TU.  Seed their
    # formals conservatively.  Functions with known in-TU callers are seeded by
    # those callers instead, preserving useful safe/unsafe distinctions.
    for name in sorted(fn_meta):
        if not graph.callers(name):
            incoming[name] = [ValueFact() for _ in incoming[name]]

    for component in reversed(graph.bottom_up_sccs):
        component = tuple(sorted(component))
        recursive = len(component) > 1 or any(name in graph.callees(name) for name in component)
        budget = config.max_iterations_per_scc if recursive else 1
        converged = not recursive

        for round_number in range(1, budget + 1):
            changed = False
            for name in component:
                params = parameter_names.get(name, ())
                entry = {
                    _canonical_location(param): fact
                    for param, fact in zip(params, incoming.get(name, ()))
                    if fact is not None
                }
                result, call_facts = _analyze_one(
                    ast_ctx,
                    name,
                    entry,
                    semantic_models,
                    summary_result.summaries,
                    config.max_provenance,
                )
                if result is not None:
                    results[name] = result

                for callee, actuals in call_facts:
                    if callee not in incoming:
                        continue
                    target = incoming[callee]
                    for index, fact in enumerate(actuals[: len(target)]):
                        old = target[index]
                        new = fact if old is None else _join_facts(old, fact, config.max_provenance)
                        if new != old:
                            target[index] = new
                            if callee in component:
                                changed = True

            if recursive and not changed:
                converged = True
                break

        if recursive and not converged:
            for name in component:
                incoming[name] = [
                    ValueFact(degradations=frozenset({"CONVERGENCE_LIMIT"}))
                    for _ in incoming[name]
                ]
            diagnostics.append(
                FixedPointDiagnostic(
                    code="CONVERGENCE_LIMIT",
                    functions=component,
                    iterations=budget,
                    message=(
                        "caller-to-formal value propagation did not converge within "
                        f"{budget} iterations; affected parameter facts were degraded "
                        "to conservative unknown"
                    ),
                )
            )

        # Once the SCC's incoming facts are stable, analyze it one final time so
        # callers querying a sink inside the component observe the final state.
        for name in component:
            params = parameter_names.get(name, ())
            entry = {
                _canonical_location(param): fact
                for param, fact in zip(params, incoming.get(name, ()))
                if fact is not None
            }
            result, _ = _analyze_one(
                ast_ctx,
                name,
                entry,
                semantic_models,
                summary_result.summaries,
                config.max_provenance,
            )
            if result is not None:
                results[name] = result

    public_params = {
        name: tuple(fact if fact is not None else ValueFact() for fact in facts)
        for name, facts in sorted(incoming.items())
    }
    return TranslationUnitValueResult(
        summaries=summary_result.summaries,
        parameter_facts=public_params,
        function_results=dict(sorted(results.items())),
        diagnostics=tuple(diagnostics),
    )


def _analyze_one(ast_ctx, function_name, entry, registry, summaries, evidence_limit):
    funcdef = find_function_def(getattr(ast_ctx, "pycparser_ast", None), function_name)
    if funcdef is None:
        return None, ()
    cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, "line_map", None))
    if not cfg.blocks:
        cfg.build_basic_blocks()
    if not cfg.blocks:
        return ValueDataflowResult({}), ()

    entry_block = cfg.node_to_block.get(cfg.entry) if cfg.entry else min(cfg.blocks)
    reachable = set()
    queue = [entry_block]
    while queue:
        bid = queue.pop(0)
        if bid in reachable or bid not in cfg.blocks:
            continue
        reachable.add(bid)
        queue.extend(cfg.blocks[bid].successors)

    incoming = {bid: {} for bid in cfg.blocks}
    incoming[entry_block] = dict(entry)
    seen = {entry_block}
    before = {}
    calls = {}
    work = [entry_block]
    while work:
        bid = work.pop(0)
        if bid not in reachable:
            continue
        state = dict(incoming[bid])
        block = cfg.blocks[bid]
        for event in block.nodes:
            before[event.node_id] = dict(state)
            for call in getattr(event, "calls", ()):
                if not call.direct_callee:
                    continue
                actuals = tuple(
                    _actual_fact(
                        text,
                        state,
                        registry,
                        summaries,
                        evidence_limit,
                    )
                    for text in call.actual_arguments
                )
                key = (event.node_id, call.direct_callee, call.actual_arguments)
                old = calls.get(key)
                if old is None:
                    calls[key] = actuals
                else:
                    calls[key] = tuple(
                        _join_facts(a, b, evidence_limit) for a, b in zip(old, actuals)
                    )
            _transfer_event(event, state, registry, summaries, evidence_limit)

        for succ in block.successors:
            if succ not in reachable:
                continue
            if succ not in seen:
                incoming[succ] = dict(state)
                seen.add(succ)
                changed = True
            else:
                merged = _merge_state(incoming[succ], state, evidence_limit)
                changed = merged != incoming[succ]
                if changed:
                    incoming[succ] = merged
            if changed and succ not in work:
                work.append(succ)

    return ValueDataflowResult(before), tuple(
        (callee, actuals) for (_, callee, _), actuals in sorted(calls.items())
    )


@lru_cache(maxsize=4096)
def _parse_actual_expression(text: str):
    """Parse one CFG actual argument back into an expression AST.

    CFG call metadata intentionally stores stable source spellings.  Re-parsing
    just the actual expression lets caller-to-formal propagation reuse the same
    semantic-model and summary-aware evaluator as ordinary assignments, rather
    than treating call expressions as variable names. Parsed ASTs are immutable
    for this analysis and cached by their deterministic source spelling.
    """
    try:
        parsed = _ACTUAL_PARSER.parse(
            f"void __cgull_actual(void) {{ __cgull_sink({text}); }}"
        )
        call = parsed.ext[0].body.block_items[0]
        args = list(getattr(getattr(call, "args", None), "exprs", ()) or ())
        return args[0] if args else None
    except Exception:
        return None


def _actual_fact(
    text: str,
    state: Mapping[str, ValueFact],
    registry: SemanticModelRegistry,
    summaries: Mapping[str, ValueFunctionSummary],
    evidence_limit: int,
) -> ValueFact:
    expression = _parse_actual_expression(text)
    if expression is not None:
        return _expression_fact(expression, state, registry, summaries, evidence_limit)

    # Keep a conservative fallback for parser-hostile spellings.  Identity
    # locations still preserve already-known facts; everything else remains
    # UNKNOWN instead of accidentally being classified as safe.
    key = _canonical_location(text.strip().lstrip("& "))
    return state.get(key, ValueFact())
