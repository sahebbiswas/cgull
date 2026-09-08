"""CFG graph representation and basic-block construction.

This layer owns nodes, edges, source locations, and block topology.  It has no
knowledge of AST event extraction or state-domain transfer semantics.
"""

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..ast_analyzer import _PRELUDE_LINE_COUNT, _map_line
from .diagnostics import CFGDiagnostic
from .model import BasicBlock, CFGEvent, CFGSourceLocation


class StructuredGraph:
    def __init__(self) -> None:
        self.nodes: Dict[int, CFGEvent] = {}
        self.edge_facts: Dict[Tuple[int, int], Tuple[Set[str], Set[str]]] = {}
        self.entry: Optional[int] = None
        self._next_id = 0
        self.blocks: Dict[int, BasicBlock] = {}
        self.node_to_block: Dict[int, int] = {}
        self.diagnostics: List[CFGDiagnostic] = []

    def add_node(self, node: CFGEvent) -> int:
        self.nodes[node.node_id] = node
        return node.node_id

    def new_node(
        self,
        kind: str,
        ast_node=None,
        line_map: Optional[Dict[int, Any]] = None,
        **kwargs,
    ) -> int:
        self._next_id += 1
        line = 1
        source_path = None
        column = 0
        coord = getattr(ast_node, "coord", None) if ast_node is not None else None
        coord_line = getattr(coord, "line", None) if coord is not None else None
        if coord_line is not None:
            exp_line = max(1, coord_line - _PRELUDE_LINE_COUNT)
            line = _map_line(exp_line, line_map)
            mapped = line_map.get(exp_line) if line_map else None
            source_path = (
                getattr(mapped, "file_path", None)
                if mapped is not None
                else getattr(coord, "file", None)
            )
            column = getattr(coord, "column", 0) or 0
        source_location = CFGSourceLocation(
            file_path=source_path,
            line_number=line,
            column_number=column,
        )
        node = CFGEvent(
            node_id=self._next_id,
            kind=kind,
            line_number=line,
            source_location=source_location,
            **kwargs,
        )
        setattr(node, "_ast_node", ast_node)
        return self.add_node(node)

    def connect(
        self,
        src: int,
        dst: Optional[int],
        *,
        add: Iterable[str] = (),
        remove: Iterable[str] = (),
    ) -> None:
        if dst is None:
            return
        if dst not in self.nodes[src].successors:
            self.nodes[src].successors.append(dst)
        self.edge_facts[(src, dst)] = (set(add), set(remove))

    def build_basic_blocks(self) -> Dict[int, BasicBlock]:
        if not self.nodes:
            return {}

        preds: Dict[int, List[int]] = {nid: [] for nid in self.nodes}
        for nid, node in self.nodes.items():
            for succ in node.successors:
                if succ in preds:
                    preds[succ].append(nid)

        leaders: Set[int] = set()
        if self.entry is not None and self.entry in self.nodes:
            leaders.add(self.entry)

        for nid, node in self.nodes.items():
            if len(preds[nid]) != 1:
                leaders.add(nid)
            for succ in node.successors:
                if len(node.successors) > 1 or node.kind.endswith("_cond"):
                    leaders.add(succ)

        self.blocks = {}
        self.node_to_block = {}
        block_id_counter = 1
        leader_to_block: Dict[int, BasicBlock] = {}

        for leader in sorted(leaders):
            b_id = block_id_counter
            block_id_counter += 1
            block = BasicBlock(block_id=b_id)

            curr = leader
            while True:
                block.nodes.append(self.nodes[curr])
                self.node_to_block[curr] = b_id

                succs = self.nodes[curr].successors
                if len(succs) == 1:
                    nxt = succs[0]
                    if nxt in leaders:
                        break
                    curr = nxt
                else:
                    break

            leader_to_block[leader] = block
            self.blocks[b_id] = block

        for leader, block in leader_to_block.items():
            last_node = block.nodes[-1]
            for succ_node_id in last_node.successors:
                succ_block = leader_to_block.get(succ_node_id)
                if succ_block:
                    if succ_block.block_id not in block.successors:
                        block.successors.append(succ_block.block_id)
                    if block.block_id not in succ_block.predecessors:
                        succ_block.predecessors.append(block.block_id)

                    edge_fact = self.edge_facts.get(
                        (last_node.node_id, succ_node_id)
                    )
                    if edge_fact:
                        block.edge_facts[succ_block.block_id] = edge_fact

        return self.blocks


__all__ = ["StructuredGraph"]
