"""Shared rule-facing queries over ownership effects."""

from __future__ import annotations

import collections
import re
from typing import Dict, Iterable, List, Mapping, Set, Tuple

from .model import CFGEvent
from .ownership import NodeOwnershipEffects


__all__ = [
    "filter_leak_exits_for_ownership",
    "find_uses_after_free_effect",
    "has_prior_free_effect",
]


def _locations(cfg, node_id: int, variable: str) -> Set[str]:
    return set(cfg.get_loc_map_at_node(node_id).get(variable, {f"var_{variable}"}))


def find_uses_after_free_effect(cfg, free_node_id: int, ptr_name: str):
    """Yield downstream accesses that still alias a location freed by a call effect."""
    freed_locations = _locations(cfg, free_node_id, ptr_name)
    work = list(cfg.nodes[free_node_id].successors)
    visited = set()
    while work:
        node_id = work.pop(0)
        if node_id in visited:
            continue
        visited.add(node_id)
        node = cfg.nodes[node_id]
        loc_map = cfg.get_loc_map_at_node(node_id)
        accessed = node.derefs | (node.reads - node.writes)
        for variable in sorted(accessed):
            if freed_locations & set(loc_map.get(variable, {f"var_{variable}"})):
                if not node.kind.endswith("_cond"):
                    yield node, variable
        for successor in node.successors:
            if successor not in visited:
                work.append(successor)


def has_prior_free_effect(
    cfg,
    node_id: int,
    ptr_name: str,
    effects: Mapping[int, NodeOwnershipEffects],
) -> bool:
    """Whether the location freed at ``node_id`` may already have been freed."""
    target_locations = _locations(cfg, node_id, ptr_name)
    predecessors: Dict[int, Set[int]] = {nid: set() for nid in cfg.nodes}
    for pred_id, node in cfg.nodes.items():
        for successor in node.successors:
            if successor in predecessors:
                predecessors[successor].add(pred_id)

    queue = collections.deque(sorted(predecessors.get(node_id, set())))
    visited = set()
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        current_effects = effects.get(current, NodeOwnershipEffects())
        for variable in current_effects.freed | current_effects.maybe_freed:
            if target_locations & _locations(cfg, current, variable):
                return True
        for predecessor in sorted(predecessors.get(current, set())):
            if predecessor not in visited:
                queue.append(predecessor)
    return False


def _extend_aliases(node, aliases: Set[str]) -> Set[str]:
    result = set(aliases)
    if node.kind not in ("assignment", "decl") or not (node.reads & aliases):
        return result
    if node.alias_writes:
        for lhs, rhs in node.alias_writes.items():
            if rhs in aliases:
                result.add(lhs)
        return result
    if node.expr_str:
        match = re.match(
            r"^\s*([A-Za-z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?([A-Za-z_]\w*)\s*;?$",
            node.expr_str,
        )
        if match and match.group(2) in aliases:
            result.add(match.group(1))
    return result


def _reaches_exit_without_consumption(
    cfg,
    alloc_node_id: int,
    ptr_name: str,
    target_exit_id: int,
    effects: Mapping[int, NodeOwnershipEffects],
) -> bool:
    start = cfg.nodes[alloc_node_id]
    queue = collections.deque((succ, frozenset({ptr_name})) for succ in start.successors)
    visited: Set[Tuple[int, Tuple[str, ...]]] = set()

    while queue:
        node_id, raw_aliases = queue.popleft()
        aliases = set(raw_aliases)
        state = (node_id, tuple(sorted(aliases)))
        if state in visited:
            continue
        visited.add(state)
        node = cfg.nodes[node_id]
        node_effects = effects.get(node_id, NodeOwnershipEffects())

        # Only definite ownership consumption suppresses a leak. Possible or
        # unknown escapes remain conservative and keep the leak path alive.
        if node_effects.consumed & aliases:
            continue
        if node.freed & aliases:
            continue

        aliases = _extend_aliases(node, aliases)
        if node_id == target_exit_id:
            return True

        overwritten = [
            variable
            for variable in node.writes
            if variable in aliases and not (node.reads & aliases)
        ]
        if overwritten:
            aliases.difference_update(overwritten)
            if not aliases:
                continue

        for successor in node.successors:
            queue.append((successor, frozenset(aliases)))
    return False


def filter_leak_exits_for_ownership(
    cfg,
    alloc_node_id: int,
    ptr_name: str,
    leak_nodes: Iterable[CFGEvent],
    effects: Mapping[int, NodeOwnershipEffects],
) -> List[CFGEvent]:
    """Drop exits whose allocation is definitely consumed before reaching them."""
    return [
        node
        for node in leak_nodes
        if _reaches_exit_without_consumption(
            cfg, alloc_node_id, ptr_name, node.node_id, effects
        )
    ]
