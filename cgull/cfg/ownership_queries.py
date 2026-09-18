"""Shared rule-facing queries over ownership effects."""

from __future__ import annotations

from collections import deque
import collections
import re
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple

from .model import Allocation, CFGEvent
from .ownership import NodeOwnershipEffects


__all__ = [
    "build_ownership_predecessors",
    "filter_leak_exits_for_ownership",
    "find_uses_after_free_effect",
    "has_prior_free_effect",
]


def _locations(cfg, node_id: int, variable: str) -> Set[str]:
    return set(cfg.get_loc_map_at_node(node_id).get(variable, {f"var_{variable}"}))


def _locations_for_aliases(cfg, node_id: int, aliases: Set[str]) -> Set[str]:
    """Return the abstract locations currently represented by ``aliases``."""
    result: Set[str] = set()
    for variable in aliases:
        result.update(_locations(cfg, node_id, variable))
    return result


def _consumes_tracked_location(
    cfg,
    node_id: int,
    aliases: Set[str],
    consumed_variables: Iterable[str],
) -> bool:
    """Whether a consumption effect targets the allocation represented by aliases.

    Rule-local alias tracking intentionally handles only simple source-level alias
    assignments.  The CFG location map is stronger for ordinary aliases, so leak
    suppression compares abstract allocation locations instead of requiring the
    consumed variable's spelling to appear in the tracked alias set.
    """
    tracked_locations = _locations_for_aliases(cfg, node_id, aliases)
    if not tracked_locations:
        return False
    for variable in consumed_variables:
        if tracked_locations & _locations(cfg, node_id, variable):
            return True
    return False


def _aliases_for_locations(cfg, node_id: int, locations: Set[str]) -> Set[str]:
    """Return variables that alias any supplied location before the node executes."""
    loc_map = cfg.get_loc_map_at_node(node_id)
    return {
        variable
        for variable, variable_locations in loc_map.items()
        if locations & set(variable_locations)
    }


def _advance_freed_aliases(node, aliases: Set[str]) -> Set[str]:
    """Apply one node's definite pointer rebindings to path-local UAF aliases."""
    previous = set(aliases)
    result = set(aliases)

    # Assignment events describe simple aliasing explicitly. Evaluate the RHS
    # against the pre-node alias state so q = p carries the freed object
    # forward, while p = live severs the tracked alias.
    for target in node.writes:
        if target in node.alias_writes:
            source = node.alias_writes[target]
            if source in previous:
                result.add(target)
            else:
                result.discard(target)
        else:
            # Allocation, NULL assignment, address rebinding, and other
            # non-alias writes all create a location distinct from the freed
            # object in the legacy location model.
            result.discard(target)

    return result


def find_uses_after_free_effect(cfg, free_node_id: int, ptr_name: str):
    """Yield downstream accesses that still alias a freed location on that path."""
    freed_locations = _locations(cfg, free_node_id, ptr_name)
    initial_aliases = _aliases_for_locations(cfg, free_node_id, freed_locations)
    initial_aliases.add(ptr_name)

    work = deque(
        (successor, frozenset(initial_aliases))
        for successor in cfg.nodes[free_node_id].successors
    )
    visited: Set[Tuple[int, frozenset[str]]] = set()
    while work:
        node_id, raw_aliases = work.popleft()
        aliases = set(raw_aliases)
        state = (node_id, raw_aliases)
        if state in visited:
            continue
        visited.add(state)

        node = cfg.nodes[node_id]
        accessed = node.derefs | (node.reads - node.writes)
        for variable in sorted(accessed & aliases):
            allocation = cfg.query_allocation(variable, node_id)
            if (
                allocation in (Allocation.FREED, Allocation.MAYBE_FREED)
                and not node.kind.endswith("_cond")
            ):
                yield node, variable

        aliases = _advance_freed_aliases(node, aliases)
        if not aliases:
            continue

        next_aliases = frozenset(aliases)
        for successor in node.successors:
            work.append((successor, next_aliases))

def build_ownership_predecessors(cfg) -> Dict[int, Set[int]]:
    """Build the predecessor map reused by backward ownership queries."""
    predecessors: Dict[int, Set[int]] = {nid: set() for nid in cfg.nodes}
    for pred_id, node in cfg.nodes.items():
        for successor in node.successors:
            if successor in predecessors:
                predecessors[successor].add(pred_id)
    return predecessors


def has_prior_free_effect(
    cfg,
    node_id: int,
    ptr_name: str,
    effects: Mapping[int, NodeOwnershipEffects],
    *,
    predecessors: Optional[Mapping[int, Set[int]]] = None,
) -> bool:
    """Whether the location freed at ``node_id`` may already have been freed."""
    target_locations = _locations(cfg, node_id, ptr_name)
    predecessor_map = predecessors if predecessors is not None else build_ownership_predecessors(cfg)

    queue = collections.deque(sorted(predecessor_map.get(node_id, set())))
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
        for predecessor in sorted(predecessor_map.get(current, set())):
            if predecessor not in visited:
                queue.append(predecessor)
    return False


def _extend_aliases(
    cfg,
    node_id: int,
    node,
    aliases: Set[str],
    node_effects: NodeOwnershipEffects,
) -> Set[str]:
    """Extend tracked aliases with local assignments and returned-alias effects."""
    result = set(aliases)

    # Ownership summaries express caller-visible aliases returned from helpers,
    # e.g. ``cleanup_ptr = identity(data)``.  Those relationships are not part
    # of the base CFG location map, so project them into this path-local alias
    # state before downstream free/transfer checks.
    tracked_locations = _locations_for_aliases(cfg, node_id, result)
    for target, source in node_effects.returned_aliases:
        if source in result or (tracked_locations & _locations(cfg, node_id, source)):
            result.add(target)

    if node.kind not in ("assignment", "decl") or not (node.reads & result):
        return result
    if node.alias_writes:
        for lhs, rhs in node.alias_writes.items():
            if rhs in result:
                result.add(lhs)
        return result
    if node.expr_str:
        match = re.match(
            r"^\s*([A-Za-z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?([A-Za-z_]\w*)\s*;?$",
            node.expr_str,
        )
        if match and match.group(2) in result:
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
        if _consumes_tracked_location(
            cfg,
            node_id,
            aliases,
            node_effects.consumed | node.freed,
        ):
            continue

        aliases = _extend_aliases(cfg, node_id, node, aliases, node_effects)
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
