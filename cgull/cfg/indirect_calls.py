"""Bounded, flow-sensitive resolution of simple C function-pointer calls."""

from dataclasses import replace
from typing import Dict, FrozenSet, Mapping, Optional, Set


TargetSet = Optional[FrozenSet[str]]  # None means unknown, empty means no value yet.


def _is_function_pointer_type(type_node) -> bool:
    node = type_node
    while node is not None:
        if type(node).__name__ == "PtrDecl" and type(getattr(node, "type", None)).__name__ == "FuncDecl":
            return True
        node = getattr(node, "type", None)
    return False


def _id_name(node):
    while node is not None:
        kind = type(node).__name__
        if kind == "Cast":
            node = node.expr
            continue
        if kind == "UnaryOp" and getattr(node, "op", None) == "&":
            node = node.expr
            continue
        break
    if node is not None and type(node).__name__ == "ID":
        return str(node.name)
    return None


def _pointer_name_from_call_expression(expression: str) -> Optional[str]:
    """Return the local pointer identifier for simple indirect call spellings."""
    expr = expression.strip()
    if expr.isidentifier():
        return expr
    if expr.startswith("(*") and expr.endswith(")"):
        candidate = expr[2:-1].strip()
        return candidate if candidate.isidentifier() else None
    if expr.startswith("*"):
        candidate = expr[1:].strip()
        return candidate if candidate.isidentifier() else None
    return None


def _join(values):
    values = list(values)
    if not values:
        return frozenset()
    if any(value is None for value in values):
        return None
    merged = set()
    for value in values:
        merged.update(value)
    return frozenset(merged)


def _transfer(ast_node, incoming: Mapping[str, TargetSet], pointer_names: Set[str], visible: Set[str]):
    state = dict(incoming)
    if ast_node is None:
        return state
    kind = type(ast_node).__name__
    target = None
    value = None
    if kind == "Decl" and getattr(ast_node, "name", None) in pointer_names:
        target = str(ast_node.name)
        value = getattr(ast_node, "init", None)
    elif kind == "Assignment":
        candidate = _id_name(getattr(ast_node, "lvalue", None))
        if candidate in pointer_names:
            target = candidate
            value = getattr(ast_node, "rvalue", None)
    if target is None:
        return state
    source = _id_name(value)
    if source in pointer_names:
        state[target] = state.get(source)
    elif source in visible:
        state[target] = frozenset((source,))
    else:
        state[target] = None
    return state


def resolve_indirect_calls(cfg, visible_functions):
    """Annotate provable indirect calls and return ``cfg`` for convenient chaining.

    The analysis intentionally understands only direct function addresses and
    local function-pointer aliases. Unknown assignments dominate joins. Different
    known branch targets are retained as a deterministic target set.
    """
    visible = set(visible_functions)
    pointer_names = set()
    for event in cfg.nodes.values():
        ast_node = getattr(event, "_ast_node", None)
        if type(ast_node).__name__ == "Decl" and getattr(ast_node, "name", None) and _is_function_pointer_type(getattr(ast_node, "type", None)):
            pointer_names.add(str(ast_node.name))
    for event in cfg.nodes.values():
        for call in event.calls:
            if call.is_indirect:
                pointer_name = _pointer_name_from_call_expression(call.callee_expression)
                if pointer_name:
                    pointer_names.add(pointer_name)
    if not pointer_names:
        return cfg

    preds = {node_id: [] for node_id in cfg.nodes}
    for node_id, event in cfg.nodes.items():
        for succ in event.successors:
            if succ in preds:
                preds[succ].append(node_id)

    ins: Dict[int, Dict[str, TargetSet]] = {node_id: {} for node_id in cfg.nodes}
    outs: Dict[int, Dict[str, TargetSet]] = {node_id: {} for node_id in cfg.nodes}
    changed = True
    while changed:
        changed = False
        for node_id in sorted(cfg.nodes):
            incoming = {}
            for name in pointer_names:
                values = [outs[p].get(name, frozenset()) for p in preds[node_id]]
                if node_id == cfg.entry:
                    values.append(None)
                incoming[name] = _join(values)
            outgoing = _transfer(getattr(cfg.nodes[node_id], "_ast_node", None), incoming, pointer_names, visible)
            if incoming != ins[node_id] or outgoing != outs[node_id]:
                ins[node_id] = incoming
                outs[node_id] = outgoing
                changed = True

    for node_id, event in cfg.nodes.items():
        rewritten = []
        for call in event.calls:
            targets = ()
            if call.is_indirect:
                pointer_name = _pointer_name_from_call_expression(call.callee_expression)
                if pointer_name in pointer_names:
                    value = ins[node_id].get(pointer_name)
                    if value:
                        targets = tuple(sorted(value))
            rewritten.append(replace(call, resolved_callees=targets))
        event.calls = tuple(rewritten)
    return cfg


__all__ = ["resolve_indirect_calls"]
