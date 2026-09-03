"""Interprocedural value provenance and format-literal facts.

This module implements the first contract-level summary domain described in
``docs/interprocedural-fact-query-contract.md``.  It deliberately remains
rule-neutral: callers query value facts at CFG events while the SCC summary
engine carries parameter/return relationships through direct calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Mapping, Optional, Set, Tuple

from ..semantic_models import EMPTY_SEMANTIC_MODELS, SemanticLocationKind, SemanticModelRegistry
from .call_graph import build_translation_unit_call_graph
from .construction import build_cfg, find_function_def
from .fixed_point import FiniteLattice, FixedPointConfig, FixedPointDiagnostic, SCCFixedPointEngine


class ValueProvenance(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class FormatLiteralness(str, Enum):
    LITERAL = "literal"
    NON_LITERAL = "non_literal"
    UNKNOWN = "unknown"


@dataclass(frozen=True, order=True)
class EvidenceRef:
    kind: str
    file_path: str = ""
    line: int = 0
    column: int = 0
    identity: str = ""


@dataclass(frozen=True)
class ValueFact:
    provenance: ValueProvenance = ValueProvenance.UNKNOWN
    format_literalness: FormatLiteralness = FormatLiteralness.UNKNOWN
    evidence: Tuple[EvidenceRef, ...] = ()
    degradations: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class ValueFunctionSummary:
    """Context-independent return transfer for one function.

    ``return_from_params`` is a relation rather than a caller-specific value.
    It lets one summary serve both safe and unsafe callers without laundering
    either.  ``return_provenance`` and ``return_literalness`` describe intrinsic
    contributions such as literals and modeled external sources.
    """

    return_from_params: FrozenSet[int] = frozenset()
    return_provenance: Optional[ValueProvenance] = None  # None is fixed-point BOTTOM.
    return_literalness: Optional[FormatLiteralness] = None
    evidence: Tuple[EvidenceRef, ...] = ()
    degradations: FrozenSet[str] = frozenset()
    is_unknown: bool = False


@dataclass(frozen=True)
class ValueSummaryAnalysisResult:
    summaries: Mapping[str, ValueFunctionSummary]
    diagnostics: Tuple[FixedPointDiagnostic, ...] = ()
    iterations_by_scc: Mapping[Tuple[str, ...], int] = None

    def __post_init__(self) -> None:
        if self.iterations_by_scc is None:
            object.__setattr__(self, "iterations_by_scc", {})


class ValueDataflowResult:
    def __init__(self, facts_before: Mapping[int, Mapping[str, ValueFact]]) -> None:
        self._facts_before = facts_before

    def query(self, location: str, node_id: int) -> ValueFact:
        return self._facts_before.get(node_id, {}).get(_canonical_location(location), ValueFact())

    def query_provenance(self, location: str, node_id: int) -> ValueProvenance:
        return self.query(location, node_id).provenance

    def query_format_literalness(self, location: str, node_id: int) -> FormatLiteralness:
        return self.query(location, node_id).format_literalness

    def query_evidence(self, location: str, node_id: int) -> Tuple[EvidenceRef, ...]:
        return self.query(location, node_id).evidence


def join_provenance(left: ValueProvenance, right: ValueProvenance) -> ValueProvenance:
    if left is ValueProvenance.UNKNOWN or right is ValueProvenance.UNKNOWN:
        return ValueProvenance.UNKNOWN
    if left is right:
        return left
    if left is ValueProvenance.MIXED or right is ValueProvenance.MIXED:
        return ValueProvenance.MIXED
    return ValueProvenance.MIXED


def join_format_literalness(
    left: FormatLiteralness, right: FormatLiteralness
) -> FormatLiteralness:
    if left is FormatLiteralness.UNKNOWN or right is FormatLiteralness.UNKNOWN:
        return FormatLiteralness.UNKNOWN
    if left is right:
        return left
    return FormatLiteralness.UNKNOWN


def _join_optional_provenance(
    left: Optional[ValueProvenance], right: Optional[ValueProvenance]
) -> Optional[ValueProvenance]:
    if left is None:
        return right
    if right is None:
        return left
    return join_provenance(left, right)


def _join_optional_literalness(
    left: Optional[FormatLiteralness], right: Optional[FormatLiteralness]
) -> Optional[FormatLiteralness]:
    if left is None:
        return right
    if right is None:
        return left
    return join_format_literalness(left, right)


def _bounded_evidence(items, limit: int) -> Tuple[EvidenceRef, ...]:
    unique = sorted(set(items))
    return tuple(unique[:limit])


def _join_facts(left: ValueFact, right: ValueFact, limit: int) -> ValueFact:
    return ValueFact(
        provenance=join_provenance(left.provenance, right.provenance),
        format_literalness=join_format_literalness(left.format_literalness, right.format_literalness),
        evidence=_bounded_evidence(left.evidence + right.evidence, limit),
        degradations=left.degradations | right.degradations,
    )


class _ValueSummaryLattice(FiniteLattice[ValueFunctionSummary]):
    def __init__(self, parameter_counts: Mapping[str, int]) -> None:
        self.parameter_counts = dict(parameter_counts)
        self.max_height = max(5, max(self.parameter_counts.values(), default=0) + 5)

    def bottom(self, symbol: str) -> ValueFunctionSummary:
        return ValueFunctionSummary()

    def join(self, left: ValueFunctionSummary, right: ValueFunctionSummary) -> ValueFunctionSummary:
        return ValueFunctionSummary(
            return_from_params=left.return_from_params | right.return_from_params,
            return_provenance=_join_optional_provenance(left.return_provenance, right.return_provenance),
            return_literalness=_join_optional_literalness(left.return_literalness, right.return_literalness),
            evidence=tuple(sorted(set(left.evidence) | set(right.evidence))),
            degradations=left.degradations | right.degradations,
            is_unknown=left.is_unknown or right.is_unknown,
        )

    def unknown(self, symbol: str, current: ValueFunctionSummary) -> ValueFunctionSummary:
        return ValueFunctionSummary(
            return_from_params=current.return_from_params | frozenset(range(self.parameter_counts.get(symbol, 0))),
            return_provenance=ValueProvenance.UNKNOWN,
            return_literalness=FormatLiteralness.UNKNOWN,
            evidence=current.evidence,
            degradations=current.degradations | {"CONVERGENCE_LIMIT"},
            is_unknown=True,
        )


def analyze_value_summaries_detailed(
    ast_ctx,
    semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS,
    *,
    fixed_point_config: Optional[FixedPointConfig] = None,
    call_graph=None,
) -> ValueSummaryAnalysisResult:
    functions = [fn for fn in getattr(ast_ctx, "functions", ()) if getattr(fn, "name", None)]
    fn_map = {fn.name: fn for fn in functions}
    if not fn_map or not getattr(ast_ctx, "has_pycparser", False) or ast_ctx.pycparser_ast is None:
        return ValueSummaryAnalysisResult({name: ValueFunctionSummary(is_unknown=True) for name in sorted(fn_map)})

    graph = call_graph or build_translation_unit_call_graph(ast_ctx)
    counts = {name: len([p for p in fn.parameters if p.name]) for name, fn in fn_map.items()}
    lattice = _ValueSummaryLattice(counts)
    config = fixed_point_config or FixedPointConfig()
    engine = SCCFixedPointEngine(graph, lattice, config)

    def transfer(name, facts, cfg):
        fn = fn_map[name]
        funcdef = find_function_def(ast_ctx.pycparser_ast, name)
        if funcdef is None:
            return lattice.unknown(name, facts[name])
        params = tuple(p.name for p in fn.parameters if p.name)
        return _summarize_function(funcdef, params, facts, semantic_models, cfg.max_provenance)

    result = engine.run(transfer)
    return ValueSummaryAnalysisResult(
        summaries=dict(sorted(result.facts.items())),
        diagnostics=result.diagnostics,
        iterations_by_scc=result.iterations_by_scc,
    )


def analyze_value_summaries(
    ast_ctx,
    semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS,
) -> Dict[str, ValueFunctionSummary]:
    return dict(analyze_value_summaries_detailed(ast_ctx, semantic_models).summaries)


def analyze_function_value_dataflow(
    ast_ctx,
    function_name: str,
    semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS,
    summaries: Optional[Mapping[str, ValueFunctionSummary]] = None,
    *,
    fixed_point_config: Optional[FixedPointConfig] = None,
) -> Optional[ValueDataflowResult]:
    funcdef = find_function_def(getattr(ast_ctx, "pycparser_ast", None), function_name)
    if funcdef is None:
        return None
    if summaries is None:
        summaries = analyze_value_summaries(ast_ctx, semantic_models)
    config = fixed_point_config or FixedPointConfig()
    cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, "line_map", None))
    return analyze_value_dataflow(cfg, semantic_models, summaries, evidence_limit=config.max_provenance)


def analyze_value_dataflow(
    cfg,
    semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS,
    summaries: Optional[Mapping[str, ValueFunctionSummary]] = None,
    *,
    evidence_limit: int = 128,
) -> ValueDataflowResult:
    summaries = summaries or {}
    if not cfg.blocks:
        cfg.build_basic_blocks()
    if not cfg.blocks:
        return ValueDataflowResult({})

    entry = cfg.node_to_block.get(cfg.entry) if cfg.entry else min(cfg.blocks)
    reachable: Set[int] = set()
    queue = [entry]
    while queue:
        bid = queue.pop(0)
        if bid in reachable or bid not in cfg.blocks:
            continue
        reachable.add(bid)
        queue.extend(cfg.blocks[bid].successors)

    incoming: Dict[int, Dict[str, ValueFact]] = {bid: {} for bid in cfg.blocks}
    seen = {entry}
    before: Dict[int, Dict[str, ValueFact]] = {}
    work = [entry]
    while work:
        bid = work.pop(0)
        if bid not in reachable:
            continue
        state = dict(incoming[bid])
        block = cfg.blocks[bid]
        for event in block.nodes:
            before[event.node_id] = dict(state)
            _transfer_event(event, state, semantic_models, summaries, evidence_limit)
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
    return ValueDataflowResult(before)


def _merge_state(left, right, limit):
    result = {}
    for key in set(left) | set(right):
        if key not in left or key not in right:
            result[key] = ValueFact(degradations=frozenset({"PATH_INCOMPLETE"}))
        else:
            result[key] = _join_facts(left[key], right[key], limit)
    return result


def _transfer_event(event, state, registry, summaries, limit):
    node = getattr(event, "_ast_node", None)
    kind = type(node).__name__ if node is not None else ""
    if kind == "Decl" and getattr(node, "init", None) is not None and getattr(node, "name", None):
        state[_canonical_location(node.name)] = _expression_fact(node.init, state, registry, summaries, limit)
    elif kind == "Assignment":
        target = _location_from_ast(getattr(node, "lvalue", None))
        if target:
            fact = _expression_fact(getattr(node, "rvalue", None), state, registry, summaries, limit)
            ev = _evidence(node, "ASSIGNMENT", target)
            state[target] = ValueFact(
                fact.provenance,
                fact.format_literalness,
                _bounded_evidence(fact.evidence + (ev,), limit),
                fact.degradations,
            )

    for call in getattr(event, "calls", ()):
        if not call.result_target:
            continue
        summary = summaries.get(call.direct_callee) if call.direct_callee else None
        model = registry.for_call(call)
        target = _canonical_location(call.result_target)
        if model.source is not None and any(o.kind is SemanticLocationKind.RETURN for o in model.source.outputs):
            ev = _call_evidence(call, "SOURCE")
            state[target] = ValueFact(ValueProvenance.UNTRUSTED, FormatLiteralness.NON_LITERAL, (ev,))
        elif summary is None and not model.is_modeled:
            ev = _call_evidence(call, "DEGRADATION")
            prior = state.get(target, ValueFact())
            state[target] = ValueFact(
                ValueProvenance.UNKNOWN,
                FormatLiteralness.UNKNOWN,
                _bounded_evidence(prior.evidence + (ev,), limit),
                prior.degradations | {"UNRESOLVED_CALL"},
            )


def _expression_fact(node, state, registry, summaries, limit) -> ValueFact:
    if node is None:
        return ValueFact(degradations=frozenset({"UNSUPPORTED_EXPRESSION"}))
    kind = type(node).__name__
    if kind == "Cast":
        return _expression_fact(node.expr, state, registry, summaries, limit)
    if kind == "ID":
        return state.get(_canonical_location(node.name), ValueFact())
    if kind in {"StructRef", "ArrayRef"}:
        location = _location_from_ast(node)
        return state.get(location, ValueFact()) if location else ValueFact()
    if kind == "Constant":
        literal = FormatLiteralness.LITERAL if getattr(node, "type", None) == "string" else FormatLiteralness.UNKNOWN
        return ValueFact(ValueProvenance.TRUSTED, literal, (_evidence(node, "SOURCE", str(getattr(node, "value", ""))),))
    if kind == "UnaryOp" and getattr(node, "op", None) in {"+", "-", "~", "!"}:
        return _expression_fact(node.expr, state, registry, summaries, limit)
    if kind == "TernaryOp":
        return _join_facts(
            _expression_fact(node.iftrue, state, registry, summaries, limit),
            _expression_fact(node.iffalse, state, registry, summaries, limit),
            limit,
        )
    if kind == "BinaryOp":
        return _join_facts(
            _expression_fact(node.left, state, registry, summaries, limit),
            _expression_fact(node.right, state, registry, summaries, limit),
            limit,
        )
    if kind == "FuncCall":
        callee = _direct_callee(node)
        if callee:
            model = registry.for_function(callee)
            if model.source is not None and any(o.kind is SemanticLocationKind.RETURN for o in model.source.outputs):
                return ValueFact(
                    ValueProvenance.UNTRUSTED,
                    FormatLiteralness.NON_LITERAL,
                    (_evidence(node, "SOURCE", callee),),
                )
            summary = summaries.get(callee)
            if summary is not None:
                result = _intrinsic_summary_fact(summary)
                args = list(getattr(getattr(node, "args", None), "exprs", ()) or ())
                for index in summary.return_from_params:
                    actual = _expression_fact(args[index], state, registry, summaries, limit) if index < len(args) else ValueFact()
                    result = actual if result is None else _join_facts(result, actual, limit)
                if result is None:
                    result = ValueFact()
                ev = _evidence(node, "CALL", callee)
                return ValueFact(
                    result.provenance,
                    result.format_literalness,
                    _bounded_evidence(result.evidence + summary.evidence + (ev,), limit),
                    result.degradations | summary.degradations,
                )
        return ValueFact(
            evidence=(_evidence(node, "DEGRADATION", callee or "indirect"),),
            degradations=frozenset({"UNRESOLVED_CALL" if callee else "INDIRECT_CALL"}),
        )
    return ValueFact(
        evidence=(_evidence(node, "DEGRADATION", kind),),
        degradations=frozenset({"UNSUPPORTED_EXPRESSION"}),
    )


def _intrinsic_summary_fact(summary: ValueFunctionSummary) -> Optional[ValueFact]:
    if summary.return_provenance is None and summary.return_literalness is None:
        return None
    return ValueFact(
        summary.return_provenance or ValueProvenance.UNKNOWN,
        summary.return_literalness or FormatLiteralness.UNKNOWN,
        summary.evidence,
        summary.degradations,
    )


def _summarize_function(funcdef, param_names, summaries, registry, limit):
    deps: Set[int] = set()
    provenance: Optional[ValueProvenance] = None
    literalness: Optional[FormatLiteralness] = None
    evidence = []
    degradations: Set[str] = set()

    def relation(node):
        nonlocal provenance, literalness
        if node is None:
            return
        kind = type(node).__name__
        if kind == "Cast":
            relation(node.expr)
        elif kind == "ID":
            try:
                deps.add(param_names.index(str(node.name)))
            except ValueError:
                provenance = _join_optional_provenance(provenance, ValueProvenance.UNKNOWN)
                literalness = _join_optional_literalness(literalness, FormatLiteralness.UNKNOWN)
        elif kind == "Constant":
            provenance = _join_optional_provenance(provenance, ValueProvenance.TRUSTED)
            if getattr(node, "type", None) == "string":
                literalness = _join_optional_literalness(literalness, FormatLiteralness.LITERAL)
            evidence.append(_evidence(node, "RETURN", str(getattr(node, "value", ""))))
        elif kind in {"UnaryOp"}:
            relation(node.expr)
        elif kind == "BinaryOp":
            relation(node.left)
            relation(node.right)
            literalness = _join_optional_literalness(literalness, FormatLiteralness.NON_LITERAL)
        elif kind == "TernaryOp":
            relation(node.iftrue)
            relation(node.iffalse)
        elif kind == "FuncCall":
            callee = _direct_callee(node)
            if not callee:
                provenance = _join_optional_provenance(provenance, ValueProvenance.UNKNOWN)
                literalness = _join_optional_literalness(literalness, FormatLiteralness.UNKNOWN)
                degradations.add("INDIRECT_CALL")
                return
            model = registry.for_function(callee)
            if model.source is not None and any(o.kind is SemanticLocationKind.RETURN for o in model.source.outputs):
                provenance = _join_optional_provenance(provenance, ValueProvenance.UNTRUSTED)
                literalness = _join_optional_literalness(literalness, FormatLiteralness.NON_LITERAL)
                evidence.append(_evidence(node, "SOURCE", callee))
                return
            summary = summaries.get(callee)
            if summary is None:
                provenance = _join_optional_provenance(provenance, ValueProvenance.UNKNOWN)
                literalness = _join_optional_literalness(literalness, FormatLiteralness.UNKNOWN)
                degradations.add("UNRESOLVED_CALL")
                return
            args = list(getattr(getattr(node, "args", None), "exprs", ()) or ())
            for index in summary.return_from_params:
                if index < len(args):
                    relation(args[index])
                else:
                    provenance = _join_optional_provenance(provenance, ValueProvenance.UNKNOWN)
                    literalness = _join_optional_literalness(literalness, FormatLiteralness.UNKNOWN)
            provenance = _join_optional_provenance(provenance, summary.return_provenance)
            literalness = _join_optional_literalness(literalness, summary.return_literalness)
            evidence.extend(summary.evidence)
            evidence.append(_evidence(node, "CALL", callee))
            degradations.update(summary.degradations)
        else:
            provenance = _join_optional_provenance(provenance, ValueProvenance.UNKNOWN)
            literalness = _join_optional_literalness(literalness, FormatLiteralness.UNKNOWN)
            degradations.add("UNSUPPORTED_EXPRESSION")

    class Visitor:
        def visit(self, node):
            if node is None:
                return
            if type(node).__name__ == "Return":
                relation(getattr(node, "expr", None))
                return
            for _, child in node.children():
                self.visit(child)

    Visitor().visit(funcdef.body)
    if len(set(evidence)) > limit:
        degradations.add("EVIDENCE_LIMIT")
    return ValueFunctionSummary(
        return_from_params=frozenset(deps),
        return_provenance=provenance,
        return_literalness=literalness,
        evidence=_bounded_evidence(evidence, limit),
        degradations=frozenset(degradations),
    )


def _evidence(node, kind: str, identity: str) -> EvidenceRef:
    coord = getattr(node, "coord", None)
    return EvidenceRef(
        kind=kind,
        file_path=str(getattr(coord, "file", "") or ""),
        line=int(getattr(coord, "line", 0) or 0),
        column=int(getattr(coord, "column", 0) or 0),
        identity=identity,
    )


def _call_evidence(call, kind: str) -> EvidenceRef:
    loc = getattr(call, "source_location", None)
    return EvidenceRef(
        kind=kind,
        file_path=str(getattr(loc, "file_path", "") or ""),
        line=int(getattr(loc, "line_number", 0) or 0),
        column=int(getattr(loc, "column_number", 0) or 0),
        identity=str(call.direct_callee or call.callee_expression),
    )


def _location_from_ast(node) -> Optional[str]:
    if node is None:
        return None
    kind = type(node).__name__
    if kind == "Cast":
        return _location_from_ast(node.expr)
    if kind == "ID":
        return _canonical_location(str(node.name))
    if kind == "StructRef":
        base = _location_from_ast(node.name)
        field = getattr(getattr(node, "field", None), "name", None)
        return _canonical_location(f"{base}.{field}") if base and field else None
    if kind == "ArrayRef":
        base = _location_from_ast(node.name)
        return _canonical_location(f"{base}[]") if base else None
    if kind == "UnaryOp" and getattr(node, "op", None) == "&":
        return _location_from_ast(node.expr)
    return None


def _canonical_location(value: Optional[str]) -> str:
    text = "" if value is None else "".join(str(value).split())
    text = text.replace("->", ".")
    result = []
    depth = 0
    for char in text:
        if char == "[":
            if depth == 0:
                result.append("[]")
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
        elif depth == 0:
            result.append(char)
    return "".join(result)


def _direct_callee(node) -> Optional[str]:
    name = getattr(node, "name", None)
    return str(name.name) if type(name).__name__ == "ID" else None
