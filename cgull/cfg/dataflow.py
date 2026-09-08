"""Compatibility facade for the core CFG graph and legacy data-flow engine.

Graph topology lives in :mod:`cgull.cfg.graph`; legacy state transfer and
queries live in :mod:`cgull.cfg.legacy_dataflow`; domain joins live in
:mod:`cgull.cfg.domains`.  This module retains the historic import surface.
"""

from .domains import meet_allocation, meet_initialization, meet_nullness
from .graph import StructuredGraph
from .legacy_dataflow import LegacyDataflowMixin
from .model import Allocation, Initialization, Nullness, VariableFacts


class StructuredCFG(LegacyDataflowMixin, StructuredGraph):
    """Historic CFG type composed from graph and data-flow responsibilities."""

    def analyze_dataflow(self, *args, **kwargs) -> None:
        super().analyze_dataflow(*args, **kwargs)
        self._degrade_unknown_control_flow_facts()

    def _degrade_unknown_control_flow_facts(self) -> None:
        """Prevent unresolved control flow from yielding spuriously precise facts."""
        unknown_ids = {
            node_id
            for node_id, node in self.nodes.items()
            if getattr(node, "is_unknown_control_flow", False)
        }
        if not unknown_ids or not hasattr(self, "node_facts"):
            return

        affected_nodes = set(unknown_ids)
        queue = list(sorted(unknown_ids))
        while queue:
            node_id = queue.pop(0)
            for succ in self.nodes[node_id].successors:
                if succ not in affected_nodes:
                    affected_nodes.add(succ)
                    queue.append(succ)

        all_vars = set()
        for facts in self.node_facts.values():
            all_vars.update(facts)

        for node_id in affected_nodes:
            facts = self.node_facts.get(node_id)
            if facts is None:
                continue
            for var_name in all_vars:
                facts[var_name] = VariableFacts(
                    nullness=Nullness.MAYBE_NULL,
                    initialization=Initialization.MAYBE_INITIALIZED,
                    allocation=Allocation.MAYBE_FREED,
                )

        affected_blocks = {
            self.node_to_block[node_id]
            for node_id in affected_nodes
            if node_id in self.node_to_block
        }
        for block_id in affected_blocks:
            block = self.blocks[block_id]
            for var_name in all_vars:
                block.nullness_in[var_name] = Nullness.MAYBE_NULL
                block.nullness_out[var_name] = Nullness.MAYBE_NULL
                block.init_in[var_name] = Initialization.MAYBE_INITIALIZED
                block.init_out[var_name] = Initialization.MAYBE_INITIALIZED
                block.alloc_in[var_name] = Allocation.MAYBE_FREED
                block.alloc_out[var_name] = Allocation.MAYBE_FREED
            for loc_id in set(block.loc_state_in) | set(block.loc_state_out):
                block.loc_state_in[loc_id] = Allocation.MAYBE_FREED
                block.loc_state_out[loc_id] = Allocation.MAYBE_FREED


__all__ = [
    "StructuredCFG",
    "meet_nullness",
    "meet_initialization",
    "meet_allocation",
]
