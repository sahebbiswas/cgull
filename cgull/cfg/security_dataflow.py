"""Rule-neutral external provenance and validation facts over the structured CFG.

The intraprocedural pass consumes :class:`StructuredCFG` events.  The optional
security summary map extends the same transfer across direct calls without
recursively analyzing callees from rule code.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Mapping, Optional, Sequence, Set, Tuple

from ..semantic_models import (
    EMPTY_SEMANTIC_MODELS,
    SemanticLocation,
    SemanticLocationKind,
    SemanticModelRegistry,
    SuccessCondition,
    SuccessConditionKind,
    ValidationProperty,
)
from .construction import build_cfg, find_function_def


class Provenance(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    MIXED = "mixed"
    UNKNOWN = "unknown"


def join_provenance(left: Provenance, right: Provenance) -> Provenance:
    """Join provenance for the may-taint domain.

    UNKNOWN is the intraprocedural representation of an unclassified
    contribution, so it is an identity for an already-classified may fact.
    """
    if left is Provenance.UNKNOWN:
        return right
    if right is Provenance.UNKNOWN:
        return left
    if left is right:
        return left
    return Provenance.MIXED


@dataclass(frozen=True)
class SecurityFacts:
    provenance: Provenance = Provenance.UNKNOWN
    validations: FrozenSet[ValidationProperty] = frozenset()


@dataclass(frozen=True)
class SecurityValidatorEffect:
    parameter_index: int
    property: ValidationProperty
    success: SuccessCondition


@dataclass(frozen=True)
class SecuritySinkRequirement:
    parameter_index: int
    properties: FrozenSet[ValidationProperty]


@dataclass(frozen=True)
class SecurityFunctionSummary:
    """Context-insensitive trust-boundary relationships for one function."""

    return_from_params: FrozenSet[int] = frozenset()
    output_from_params: Tuple[Tuple[int, FrozenSet[int]], ...] = ()
    external_return: bool = False
    external_outputs: FrozenSet[int] = frozenset()
    validator_effects: Tuple[SecurityValidatorEffect, ...] = ()
    sink_requirements: Tuple[SecuritySinkRequirement, ...] = ()

    def output_dependencies(self, index: int) -> FrozenSet[int]:
        for output_index, deps in self.output_from_params:
            if output_index == index:
                return deps
        return frozenset()


class SecurityDataflowResult:
    """Security facts immediately before each CFG event."""

    def __init__(
        self,
        provenance_before: Mapping[int, Mapping[str, Provenance]],
        validations_before: Mapping[int, Mapping[str, FrozenSet[ValidationProperty]]],
    ) -> None:
        self._provenance_before = provenance_before
        self._validations_before = validations_before

    def query_provenance(self, location: str, node_id: int) -> Provenance:
        return self._provenance_before.get(node_id, {}).get(
            _canonical_location(location), Provenance.UNKNOWN
        )

    def query_validation_properties(
        self, location: str, node_id: int
    ) -> FrozenSet[ValidationProperty]:
        return self._validations_before.get(node_id, {}).get(
            _canonical_location(location), frozenset()
        )

    def query(self, location: str, node_id: int) -> SecurityFacts:
        return SecurityFacts(
            provenance=self.query_provenance(location, node_id),
            validations=self.query_validation_properties(location, node_id),
        )


def analyze_security_dataflow(
    cfg,
    semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS,
    summaries: Optional[Mapping[str, SecurityFunctionSummary]] = None,
) -> SecurityDataflowResult:
    """Compute provenance and guaranteed validation facts on ``cfg``."""
    summaries = summaries or {}
    if not cfg.blocks:
        cfg.build_basic_blocks()
    if not cfg.blocks:
        return SecurityDataflowResult({}, {})

    entry_block_id = cfg.node_to_block.get(cfg.entry) if cfg.entry else min(cfg.blocks)
    reachable: Set[int] = set()
    queue = [entry_block_id]
    while queue:
        block_id = queue.pop(0)
        if block_id in reachable or block_id not in cfg.blocks:
            continue
        reachable.add(block_id)
        queue.extend(cfg.blocks[block_id].successors)

    prov_in: Dict[int, Dict[str, Provenance]] = {bid: {} for bid in cfg.blocks}
    val_in: Dict[int, Dict[str, FrozenSet[ValidationProperty]]] = {bid: {} for bid in cfg.blocks}
    seen_incoming: Set[int] = {entry_block_id}
    provenance_before: Dict[int, Dict[str, Provenance]] = {}
    validations_before: Dict[int, Dict[str, FrozenSet[ValidationProperty]]] = {}

    worklist = [entry_block_id]
    while worklist:
        block_id = worklist.pop(0)
        if block_id not in reachable:
            continue
        block = cfg.blocks[block_id]
        provenance = dict(prov_in[block_id])
        validations = dict(val_in[block_id])

        for node in block.nodes:
            provenance_before[node.node_id] = dict(provenance)
            validations_before[node.node_id] = dict(validations)
            _transfer_event(node, provenance, validations, semantic_models, summaries)

        last = block.nodes[-1]
        for succ_index, succ_id in enumerate(block.successors):
            if succ_id not in reachable:
                continue
            edge_prov = dict(provenance)
            edge_val = dict(validations)
            _apply_validator_edge(last, succ_index, edge_val, semantic_models, summaries)

            changed = False
            if succ_id not in seen_incoming:
                prov_in[succ_id] = edge_prov
                val_in[succ_id] = edge_val
                seen_incoming.add(succ_id)
                changed = True
            else:
                merged_prov = _merge_provenance_maps(prov_in[succ_id], edge_prov)
                merged_val = _merge_validation_maps(val_in[succ_id], edge_val)
                if merged_prov != prov_in[succ_id]:
                    prov_in[succ_id] = merged_prov
                    changed = True
                if merged_val != val_in[succ_id]:
                    val_in[succ_id] = merged_val
                    changed = True
            if changed and succ_id not in worklist:
                worklist.append(succ_id)

    result = SecurityDataflowResult(provenance_before, validations_before)
    cfg.security_dataflow = result
    return result


def analyze_security_summaries(
    ast_ctx,
    semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS,
) -> Dict[str, SecurityFunctionSummary]:
    """Compute direct-call security summaries to a bounded fixed point.

    The iteration is monotone over finite parameter/property sets, so recursive
    SCCs converge deterministically.  The explicit cap is retained as a guard
    against malformed parser input rather than as the convergence mechanism.
    """
    if not getattr(ast_ctx, "has_pycparser", False) or getattr(ast_ctx, "pycparser_ast", None) is None:
        return {}
    fn_map = {
        fn.name: fn
        for fn in getattr(ast_ctx, "functions", ())
        if getattr(fn, "name", None)
    }
    summaries: Dict[str, SecurityFunctionSummary] = {
        name: SecurityFunctionSummary() for name in fn_map
    }
    max_iters = max(1, len(fn_map) * 4 + 8)
    for _ in range(max_iters):
        changed = False
        for name, fn in fn_map.items():
            funcdef = find_function_def(ast_ctx.pycparser_ast, name)
            if funcdef is None:
                continue
            param_names = tuple(p.name for p in fn.parameters if p.name)
            new_summary = _summarize_function(
                funcdef, param_names, summaries, semantic_models
            )
            if new_summary != summaries[name]:
                summaries[name] = new_summary
                changed = True
        if not changed:
            break
    return summaries


def analyze_function_security_dataflow(
    ast_ctx,
    function_name: str,
    semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS,
    summaries: Optional[Mapping[str, SecurityFunctionSummary]] = None,
) -> Optional[SecurityDataflowResult]:
    """Shared per-TU query entry point used by rule consumers."""
    if not getattr(ast_ctx, "has_pycparser", False) or getattr(ast_ctx, "pycparser_ast", None) is None:
        return None
    funcdef = find_function_def(ast_ctx.pycparser_ast, function_name)
    if funcdef is None:
        return None
    if summaries is None:
        summaries = analyze_security_summaries(ast_ctx, semantic_models)
    cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, "line_map", None))
    return analyze_security_dataflow(cfg, semantic_models, summaries)


def query_provenance(cfg, location: str, node_id: int) -> Provenance:
    result = getattr(cfg, "security_dataflow", None)
    if result is None:
        result = analyze_security_dataflow(cfg)
    return result.query_provenance(location, node_id)


def query_validation_properties(
    cfg, location: str, node_id: int
) -> FrozenSet[ValidationProperty]:
    result = getattr(cfg, "security_dataflow", None)
    if result is None:
        result = analyze_security_dataflow(cfg)
    return result.query_validation_properties(location, node_id)


def _merge_provenance_maps(
    left: Mapping[str, Provenance], right: Mapping[str, Provenance]
) -> Dict[str, Provenance]:
    merged: Dict[str, Provenance] = {}
    for location in set(left) | set(right):
        merged[location] = join_provenance(
            left.get(location, Provenance.UNKNOWN),
            right.get(location, Provenance.UNKNOWN),
        )
    return merged


def _merge_validation_maps(
    left: Mapping[str, FrozenSet[ValidationProperty]],
    right: Mapping[str, FrozenSet[ValidationProperty]],
) -> Dict[str, FrozenSet[ValidationProperty]]:
    merged: Dict[str, FrozenSet[ValidationProperty]] = {}
    for location in set(left) | set(right):
        common = left.get(location, frozenset()) & right.get(location, frozenset())
        if common:
            merged[location] = frozenset(common)
    return merged


def _transfer_event(node, provenance, validations, registry, summaries) -> None:
    ast_node = getattr(node, "_ast_node", None)
    kind = type(ast_node).__name__ if ast_node is not None else ""

    if kind == "Decl" and getattr(ast_node, "init", None) is not None and getattr(ast_node, "name", None):
        target = _canonical_location(str(ast_node.name))
        _assign(target, ast_node.init, provenance, validations, registry, summaries)
    elif kind == "Assignment":
        target = _location_from_ast(getattr(ast_node, "lvalue", None))
        if target is not None:
            _assign(target, getattr(ast_node, "rvalue", None), provenance, validations, registry, summaries)

    for call in getattr(node, "calls", ()):
        model = registry.for_call(call)
        if model.source is not None:
            for output in model.source.outputs:
                target = _resolve_semantic_location(call, output)
                if target is not None:
                    provenance[target] = Provenance.UNTRUSTED
                    validations.pop(target, None)

        summary = summaries.get(call.direct_callee) if call.direct_callee else None
        if summary is not None:
            _apply_summary_call(call, summary, provenance, validations)
            continue

        if not model.is_modeled and (call.is_indirect or not call.direct_callee):
            if call.result_target:
                target = _canonical_location(call.result_target)
                provenance[target] = Provenance.UNKNOWN
                validations.pop(target, None)
            # Unknown calls may mutate referenced storage.  Never preserve a
            # validation proof across a passed address.
            for actual in call.actual_arguments:
                if actual.lstrip().startswith("&"):
                    validations.pop(_canonical_location(actual.lstrip("& ")), None)


def _apply_summary_call(call, summary, provenance, validations) -> None:
    if call.result_target:
        target = _canonical_location(call.result_target)
        value = Provenance.UNTRUSTED if summary.external_return else Provenance.UNKNOWN
        for index in summary.return_from_params:
            value = join_provenance(value, _actual_provenance(call, index, provenance))
        provenance[target] = value
        validations.pop(target, None)

    output_indexes = set(summary.external_outputs)
    output_indexes.update(index for index, _ in summary.output_from_params)
    for output_index in output_indexes:
        target = _actual_output_location(call, output_index)
        if target is None:
            continue
        value = Provenance.UNTRUSTED if output_index in summary.external_outputs else Provenance.UNKNOWN
        for param_index in summary.output_dependencies(output_index):
            value = join_provenance(value, _actual_provenance(call, param_index, provenance))
        provenance[target] = value
        validations.pop(target, None)


def _actual_provenance(call, index, provenance) -> Provenance:
    if index >= len(call.actual_arguments):
        return Provenance.UNKNOWN
    return provenance.get(_canonical_location(call.actual_arguments[index].lstrip("& ")), Provenance.UNKNOWN)


def _actual_output_location(call, index) -> Optional[str]:
    if index >= len(call.actual_arguments):
        return None
    return _canonical_location(call.actual_arguments[index].lstrip("& "))


def _assign(target, rhs, provenance, validations, registry, summaries) -> None:
    source_location = _identity_location(rhs)
    provenance[target] = _expression_provenance(rhs, provenance, registry, summaries)
    if source_location is None:
        validations.pop(target, None)
    else:
        props = validations.get(source_location, frozenset())
        if props:
            validations[target] = props
        else:
            validations.pop(target, None)


def _expression_provenance(node, provenance, registry, summaries) -> Provenance:
    if node is None:
        return Provenance.UNKNOWN
    kind = type(node).__name__
    if kind == "Cast":
        return _expression_provenance(node.expr, provenance, registry, summaries)
    if kind == "ID":
        return provenance.get(_canonical_location(str(node.name)), Provenance.UNKNOWN)
    if kind in {"StructRef", "ArrayRef"}:
        location = _location_from_ast(node)
        return provenance.get(location, Provenance.UNKNOWN) if location else Provenance.UNKNOWN
    if kind == "Constant":
        return Provenance.TRUSTED
    if kind == "UnaryOp":
        if getattr(node, "op", None) in {"+", "-", "~", "!"}:
            return _expression_provenance(node.expr, provenance, registry, summaries)
        return Provenance.UNKNOWN
    if kind == "TernaryOp":
        return join_provenance(
            _expression_provenance(node.iftrue, provenance, registry, summaries),
            _expression_provenance(node.iffalse, provenance, registry, summaries),
        )
    if kind == "BinaryOp":
        return join_provenance(
            _expression_provenance(node.left, provenance, registry, summaries),
            _expression_provenance(node.right, provenance, registry, summaries),
        )
    if kind == "FuncCall":
        direct = _direct_callee(node)
        if direct:
            model = registry.for_function(direct)
            if model.source is not None and any(
                loc.kind is SemanticLocationKind.RETURN for loc in model.source.outputs
            ):
                return Provenance.UNTRUSTED
            summary = summaries.get(direct)
            if summary is not None:
                value = Provenance.UNTRUSTED if summary.external_return else Provenance.UNKNOWN
                args = list(getattr(getattr(node, "args", None), "exprs", ()) or ())
                for index in summary.return_from_params:
                    if index < len(args):
                        value = join_provenance(
                            value,
                            _expression_provenance(args[index], provenance, registry, summaries),
                        )
                return value
        return Provenance.UNKNOWN
    return Provenance.UNKNOWN


def _apply_validator_edge(node, successor_index, validations, registry, summaries) -> None:
    if getattr(node, "kind", "") not in {"if_cond", "while_cond", "do_cond", "for_cond"}:
        return
    edge_is_true = successor_index == 0
    cond = getattr(getattr(node, "_ast_node", None), "cond", None)
    if cond is None:
        return

    for call in getattr(node, "calls", ()):
        effects = []
        validator = registry.validator_for(call)
        if validator is not None:
            index = validator.target.argument_index
            if index is not None:
                effects.append((index, validator.property, validator.success))
        summary = summaries.get(call.direct_callee) if call.direct_callee else None
        if summary is not None:
            effects.extend(
                (effect.parameter_index, effect.property, effect.success)
                for effect in summary.validator_effects
            )

        for index, prop, success in effects:
            true_success, false_success = _condition_guarantees_success(
                cond, call.direct_callee or "", success
            )
            if not ((edge_is_true and true_success) or ((not edge_is_true) and false_success)):
                continue
            target = _actual_output_or_value_location(call, index)
            if target is not None:
                props = set(validations.get(target, frozenset()))
                props.add(prop)
                validations[target] = frozenset(props)


def _summarize_function(funcdef, param_names, summaries, registry) -> SecurityFunctionSummary:
    return_deps: Set[int] = set()
    output_deps: Dict[int, Set[int]] = {}
    external_return = False
    external_outputs: Set[int] = set()
    validator_effects: Set[SecurityValidatorEffect] = set()
    sink_requirements: Set[SecuritySinkRequirement] = set()

    def param_deps(node) -> Set[int]:
        if node is None:
            return set()
        kind = type(node).__name__
        if kind == "ID":
            try:
                return {param_names.index(str(node.name))}
            except ValueError:
                return set()
        if kind == "Cast":
            return param_deps(node.expr)
        if kind == "UnaryOp":
            return param_deps(node.expr)
        if kind == "BinaryOp":
            return param_deps(node.left) | param_deps(node.right)
        if kind == "TernaryOp":
            return param_deps(node.iftrue) | param_deps(node.iffalse)
        if kind in {"StructRef", "ArrayRef"}:
            return param_deps(node.name)
        if kind == "FuncCall":
            callee = _direct_callee(node)
            summary = summaries.get(callee) if callee else None
            args = list(getattr(getattr(node, "args", None), "exprs", ()) or ())
            deps: Set[int] = set()
            if summary is not None:
                for index in summary.return_from_params:
                    if index < len(args):
                        deps.update(param_deps(args[index]))
            return deps
        return set()

    class Visitor:
        def visit(self, node):
            nonlocal external_return
            if node is None:
                return
            kind = type(node).__name__
            if kind == "Return":
                return_deps.update(param_deps(getattr(node, "expr", None)))
                expr = getattr(node, "expr", None)
                if type(expr).__name__ == "FuncCall":
                    callee = _direct_callee(expr)
                    if callee:
                        model = registry.for_function(callee)
                        summary = summaries.get(callee)
                        if model.source is not None and any(
                            loc.kind is SemanticLocationKind.RETURN for loc in model.source.outputs
                        ):
                            external_return = True
                        if summary is not None and summary.external_return:
                            external_return = True
            if kind == "FuncCall":
                self.visit_call(node)
            for _, child in node.children():
                self.visit(child)

        def visit_call(self, node):
            callee = _direct_callee(node)
            if not callee:
                return
            args = list(getattr(getattr(node, "args", None), "exprs", ()) or ())
            model = registry.for_function(callee)
            summary = summaries.get(callee)

            if model.source is not None:
                for output in model.source.outputs:
                    if output.kind is SemanticLocationKind.OUTPUT_ARGUMENT and output.argument_index is not None:
                        idx = output.argument_index
                        if idx < len(args):
                            for p in param_deps(args[idx]):
                                external_outputs.add(p)
            if model.validator is not None and model.validator.target.argument_index is not None:
                idx = model.validator.target.argument_index
                if idx < len(args):
                    for p in param_deps(args[idx]):
                        validator_effects.add(
                            SecurityValidatorEffect(p, model.validator.property, model.validator.success)
                        )
            if model.sink is not None:
                for req in model.sink.requirements:
                    idx = req.location.argument_index
                    if idx is not None and idx < len(args):
                        for p in param_deps(args[idx]):
                            sink_requirements.add(SecuritySinkRequirement(p, req.properties))

            if summary is None:
                return
            for effect in summary.validator_effects:
                if effect.parameter_index < len(args):
                    for p in param_deps(args[effect.parameter_index]):
                        validator_effects.add(SecurityValidatorEffect(p, effect.property, effect.success))
            for req in summary.sink_requirements:
                if req.parameter_index < len(args):
                    for p in param_deps(args[req.parameter_index]):
                        sink_requirements.add(SecuritySinkRequirement(p, req.properties))
            for out_index in summary.external_outputs:
                if out_index < len(args):
                    for p in param_deps(args[out_index]):
                        external_outputs.add(p)
            for out_index, deps in summary.output_from_params:
                if out_index >= len(args):
                    continue
                targets = param_deps(args[out_index])
                for target_param in targets:
                    mapped: Set[int] = set()
                    for dep_index in deps:
                        if dep_index < len(args):
                            mapped.update(param_deps(args[dep_index]))
                    if mapped:
                        output_deps.setdefault(target_param, set()).update(mapped)

    Visitor().visit(funcdef.body)
    return SecurityFunctionSummary(
        return_from_params=frozenset(return_deps),
        output_from_params=tuple(
            sorted((index, frozenset(deps)) for index, deps in output_deps.items())
        ),
        external_return=external_return,
        external_outputs=frozenset(external_outputs),
        validator_effects=tuple(sorted(validator_effects, key=lambda e: (e.parameter_index, e.property.value, e.success.kind.value, e.success.value or 0))),
        sink_requirements=tuple(sorted(sink_requirements, key=lambda r: (r.parameter_index, tuple(sorted(p.value for p in r.properties))))),
    )


def _condition_guarantees_success(node, function: str, success) -> Tuple[bool, bool]:
    if node is None:
        return False, False
    kind = type(node).__name__
    if kind == "Cast":
        return _condition_guarantees_success(node.expr, function, success)
    if kind == "UnaryOp" and getattr(node, "op", None) == "!":
        t, f = _condition_guarantees_success(node.expr, function, success)
        return f, t
    if kind == "BinaryOp" and getattr(node, "op", None) in {"&&", "||"}:
        lt, lf = _condition_guarantees_success(node.left, function, success)
        rt, rf = _condition_guarantees_success(node.right, function, success)
        if node.op == "&&":
            return lt or rt, lf and rf
        return lt and rt, lf or rf
    if kind == "BinaryOp" and getattr(node, "op", None) in {"==", "!="}:
        call_node, const_node = _call_constant_pair(node.left, node.right, function)
        if call_node is not None:
            value = _integer_constant(const_node)
            if value is not None:
                success_when_equal = _success_equals(success, value)
                if node.op == "==":
                    return success_when_equal, not success_when_equal
                return not success_when_equal, success_when_equal
    if kind == "FuncCall" and _direct_callee(node) == function:
        if success.kind is SuccessConditionKind.RETURN_NONZERO:
            return True, False
        if success.kind is SuccessConditionKind.RETURN_ZERO:
            return False, True
    return False, False


def _success_equals(success, value: int) -> bool:
    if success.kind is SuccessConditionKind.RETURN_EQUALS:
        return value == success.value
    if success.kind is SuccessConditionKind.RETURN_ZERO:
        return value == 0
    if success.kind is SuccessConditionKind.RETURN_NONZERO:
        return value != 0
    return False


def _call_constant_pair(left, right, function):
    if type(left).__name__ == "FuncCall" and _direct_callee(left) == function and type(right).__name__ == "Constant":
        return left, right
    if type(right).__name__ == "FuncCall" and _direct_callee(right) == function and type(left).__name__ == "Constant":
        return right, left
    return None, None


def _integer_constant(node) -> Optional[int]:
    try:
        return int(str(node.value), 0)
    except (AttributeError, TypeError, ValueError):
        return None


def _resolve_semantic_location(call, location: SemanticLocation) -> Optional[str]:
    if location.kind is SemanticLocationKind.RETURN:
        return _canonical_location(call.result_target) if call.result_target else None
    index = location.argument_index
    if index is None or index >= len(call.actual_arguments):
        return None
    actual = call.actual_arguments[index]
    if location.kind is SemanticLocationKind.OUTPUT_ARGUMENT:
        actual = actual.lstrip("& ")
    return _canonical_location(actual)


def _actual_output_or_value_location(call, index: int) -> Optional[str]:
    if index >= len(call.actual_arguments):
        return None
    return _canonical_location(call.actual_arguments[index].lstrip("& "))


def _identity_location(node) -> Optional[str]:
    while node is not None and type(node).__name__ == "Cast":
        node = node.expr
    if node is None:
        return None
    if type(node).__name__ in {"ID", "StructRef", "ArrayRef"}:
        return _location_from_ast(node)
    return None


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
        if base and field:
            return _canonical_location(f"{base}.{field}")
        return None
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
    if type(name).__name__ == "ID":
        return str(name.name)
    return None
