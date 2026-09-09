"""Reusable buffer-capacity contracts for bounds-sensitive analyses.

Contracts are explicit: they come from semantic model metadata or C array
parameters whose ``static`` bound encodes a minimum element capacity. Parameter
names are never used heuristically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Optional, Tuple

from pycparser import c_ast


@dataclass(frozen=True)
class BufferCapacityContract:
    buffer: str
    bound: str
    unit: str = "elements"


def _semantic_contracts(rule, fn) -> Tuple[BufferCapacityContract, ...]:
    registry = getattr(rule, "_semantic_models", None)
    call_effects = getattr(registry, "call_effects", None)
    model = call_effects.for_function(fn.name) if call_effects is not None else None
    if model is None:
        return ()

    result = []
    for buffer_index, size_index, unit in getattr(model, "buffer_capacities", ()):
        if buffer_index >= len(fn.parameters) or size_index >= len(fn.parameters):
            continue
        buffer_param = fn.parameters[buffer_index]
        size_param = fn.parameters[size_index]
        if not buffer_param.name or not size_param.name:
            continue
        result.append(BufferCapacityContract(buffer_param.name, size_param.name, unit))
    return tuple(result)


def _static_array_contracts(funcdef) -> Tuple[BufferCapacityContract, ...]:
    """Recover ``T buf[static count]`` parameter contracts from pycparser."""
    result = []
    args = getattr(getattr(funcdef.decl.type, "args", None), "params", None) or []
    for param in args:
        if not isinstance(param, c_ast.Decl) or not isinstance(param.type, c_ast.ArrayDecl):
            continue
        if "static" not in (param.type.dim_quals or []):
            continue
        if not isinstance(param.type.dim, c_ast.ID):
            continue
        if param.name:
            result.append(BufferCapacityContract(param.name, param.type.dim.name, "elements"))
    return tuple(result)


def function_contracts(rule, fn, funcdef, element_sizes: Mapping[str, Optional[int]]) -> Dict[str, str]:
    """Return direct parameter element-capacity relations for one function.

    Byte contracts are accepted only when the pointee size is exactly one byte;
    otherwise ``index < byte_count`` does not prove an element index is safe.
    """
    result: Dict[str, str] = {}
    contracts = (*_semantic_contracts(rule, fn), *_static_array_contracts(funcdef))
    for contract in contracts:
        if contract.unit == "elements":
            result[contract.buffer] = contract.bound
        elif contract.unit == "bytes" and element_sizes.get(contract.buffer) == 1:
            result[contract.buffer] = contract.bound
    return result


def capacity_in_states(cfg, initial: Mapping[str, str]) -> Dict[int, Dict[str, str]]:
    """Propagate symbolic capacity relations through local pointer aliases.

    A relation survives only when all incoming paths agree. Reassigning either
    the pointer or its bound invalidates the corresponding fact. Simple aliases
    (``alias = buffer`` or declaration initializers) preserve the relation.
    """
    predecessors = {node_id: [] for node_id in cfg.nodes}
    for node_id, node in cfg.nodes.items():
        for successor in node.successors:
            if successor in predecessors:
                predecessors[successor].append(node_id)

    def assignment(ast_node):
        if isinstance(ast_node, c_ast.Decl) and ast_node.name and ast_node.init is not None:
            return ast_node.name, ast_node.init
        if isinstance(ast_node, c_ast.Assignment) and isinstance(ast_node.lvalue, c_ast.ID):
            return ast_node.lvalue.name, ast_node.rvalue if ast_node.op == "=" else None
        return None, None

    def alias_source(expr) -> Optional[str]:
        while isinstance(expr, c_ast.Cast):
            expr = expr.expr
        return expr.name if isinstance(expr, c_ast.ID) else None

    def transfer(state: Dict[str, str], node) -> Dict[str, str]:
        result = dict(state)
        written = set(getattr(node, "writes", set()))

        # A write to a bound parameter invalidates every relation tied to it.
        invalid_bounds = written & set(result.values())
        if invalid_bounds:
            result = {name: bound for name, bound in result.items() if bound not in invalid_bounds}

        target, rhs = assignment(getattr(node, "_ast_node", None))
        if target:
            result.pop(target, None)
            if rhs is not None:
                source = alias_source(rhs)
                if source in state and state[source] not in invalid_bounds:
                    result[target] = state[source]
        else:
            for name in written:
                result.pop(name, None)
        return result

    def merge(states: Iterable[Dict[str, str]]) -> Dict[str, str]:
        states = list(states)
        if not states:
            return {}
        common = set(states[0])
        for state in states[1:]:
            common.intersection_update(state)
        return {
            name: states[0][name]
            for name in common
            if all(state[name] == states[0][name] for state in states[1:])
        }

    if cfg.entry is None:
        return {}
    in_states: Dict[int, Dict[str, str]] = {cfg.entry: dict(initial)}
    out_states: Dict[int, Dict[str, str]] = {}
    worklist = [cfg.entry]
    while worklist:
        node_id = worklist.pop(0)
        new_out = transfer(in_states[node_id], cfg.nodes[node_id])
        if out_states.get(node_id) == new_out:
            continue
        out_states[node_id] = new_out
        for successor in cfg.nodes[node_id].successors:
            incoming = [out_states[pred] for pred in predecessors[successor] if pred in out_states]
            if not incoming:
                continue
            new_in = merge(incoming)
            if in_states.get(successor) != new_in:
                in_states[successor] = new_in
                worklist.append(successor)
    return in_states
