"""Rule-neutral external provenance and validation facts over the structured CFG.

This pass deliberately reuses :class:`StructuredCFG` blocks/events rather than
building a second control-flow representation.  Provenance is a may property;
validation is a must property and therefore intersects at control-flow joins.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Mapping, Optional, Set, Tuple

from ..semantic_models import (
    EMPTY_SEMANTIC_MODELS,
    SemanticLocation,
    SemanticLocationKind,
    SemanticModelRegistry,
    SuccessConditionKind,
    ValidationProperty,
)


class Provenance(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    MIXED = "mixed"
    UNKNOWN = "unknown"


def join_provenance(left: Provenance, right: Provenance) -> Provenance:
    """Join provenance according to the interprocedural fact contract."""
    if left is Provenance.UNKNOWN or right is Provenance.UNKNOWN:
        return Provenance.UNKNOWN
    if left is right:
        return left
    if left is Provenance.MIXED or right is Provenance.MIXED:
        return Provenance.MIXED
    return Provenance.MIXED


@dataclass(frozen=True)
class SecurityFacts:
    provenance: Provenance = Provenance.UNKNOWN
    validations: FrozenSet[ValidationProperty] = frozenset()


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
) -> SecurityDataflowResult:
    """Compute external provenance and guaranteed validation facts on ``cfg``.

    The pass consumes the existing basic-block graph and structured call events.
    It is intentionally index-insensitive for arrays and supports named struct
    members as stable projected locations.
    """
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
            _transfer_event(node, provenance, validations, semantic_models)

        last = block.nodes[-1]
        for succ_index, succ_id in enumerate(block.successors):
            if succ_id not in reachable:
                continue
            edge_prov = dict(provenance)
            edge_val = dict(validations)
            _apply_validator_edge(last, succ_index, edge_val, semantic_models)

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
        # Missing on one reachable path means the origin is not classified.
        lval = left.get(location, Provenance.UNKNOWN)
        rval = right.get(location, Provenance.UNKNOWN)
        merged[location] = join_provenance(lval, rval)
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


def _transfer_event(node, provenance, validations, registry: SemanticModelRegistry) -> None:
    ast_node = getattr(node, "_ast_node", None)
    kind = type(ast_node).__name__ if ast_node is not None else ""

    # Apply ordinary assignment/declaration transfer first.  Modeled source
    # calls below then override the call-produced locations as untrusted.
    if kind == "Decl" and getattr(ast_node, "init", None) is not None and getattr(ast_node, "name", None):
        target = _canonical_location(str(ast_node.name))
        _assign(target, ast_node.init, provenance, validations, registry)
    elif kind == "Assignment":
        target = _location_from_ast(getattr(ast_node, "lvalue", None))
        if target is not None:
            _assign(target, getattr(ast_node, "rvalue", None), provenance, validations, registry)

    for call in getattr(node, "calls", ()):
        model = registry.for_call(call)
        if not model.is_modeled:
            if call.is_indirect or not call.direct_callee:
                if call.result_target:
                    target = _canonical_location(call.result_target)
                    provenance[target] = Provenance.UNKNOWN
                    validations.pop(target, None)
            continue

        if model.source is not None:
            for output in model.source.outputs:
                target = _resolve_semantic_location(call, output)
                if target is not None:
                    provenance[target] = Provenance.UNTRUSTED
                    validations.pop(target, None)


def _assign(target, rhs, provenance, validations, registry) -> None:
    source_location = _identity_location(rhs)
    provenance[target] = _expression_provenance(rhs, provenance, registry)
    if source_location is None:
        validations.pop(target, None)
    else:
        props = validations.get(source_location, frozenset())
        if props:
            validations[target] = props
        else:
            validations.pop(target, None)


def _expression_provenance(node, provenance, registry) -> Provenance:
    if node is None:
        return Provenance.UNKNOWN
    kind = type(node).__name__
    if kind == "Cast":
        return _expression_provenance(node.expr, provenance, registry)
    if kind == "ID":
        return provenance.get(_canonical_location(str(node.name)), Provenance.UNKNOWN)
    if kind in {"StructRef", "ArrayRef"}:
        location = _location_from_ast(node)
        return provenance.get(location, Provenance.UNKNOWN) if location else Provenance.UNKNOWN
    if kind == "Constant":
        return Provenance.TRUSTED
    if kind == "UnaryOp":
        if getattr(node, "op", None) in {"+", "-", "~", "!"}:
            return _expression_provenance(node.expr, provenance, registry)
        return Provenance.UNKNOWN
    if kind == "TernaryOp":
        return join_provenance(
            _expression_provenance(node.iftrue, provenance, registry),
            _expression_provenance(node.iffalse, provenance, registry),
        )
    if kind == "BinaryOp":
        return join_provenance(
            _expression_provenance(node.left, provenance, registry),
            _expression_provenance(node.right, provenance, registry),
        )
    if kind == "FuncCall":
        direct = _direct_callee(node)
        if direct:
            model = registry.for_function(direct)
            if model.source is not None and any(
                loc.kind is SemanticLocationKind.RETURN for loc in model.source.outputs
            ):
                return Provenance.UNTRUSTED
        return Provenance.UNKNOWN
    return Provenance.UNKNOWN


def _apply_validator_edge(node, successor_index, validations, registry) -> None:
    if getattr(node, "kind", "") not in {"if_cond", "while_cond", "do_cond", "for_cond"}:
        return
    # CFG construction adds the true edge first and false edge second for these
    # condition kinds.
    edge_is_true = successor_index == 0
    cond = getattr(getattr(node, "_ast_node", None), "cond", None)
    if cond is None:
        return

    for call in getattr(node, "calls", ()):
        validator = registry.validator_for(call)
        if validator is None:
            continue
        true_success, false_success = _condition_guarantees_success(cond, validator.function, validator.success)
        if (edge_is_true and true_success) or ((not edge_is_true) and false_success):
            target = _resolve_semantic_location(call, validator.target)
            if target is not None:
                props = set(validations.get(target, frozenset()))
                props.add(validator.property)
                validations[target] = frozenset(props)


def _condition_guarantees_success(node, function: str, success) -> Tuple[bool, bool]:
    """Return whether true/false evaluation guarantees validator success."""
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
    # Deliberately collapse all array indexes to one Elements projection.
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
