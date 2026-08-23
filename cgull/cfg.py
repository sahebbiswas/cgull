"""Small, path-sensitive control-flow graph builder for C-GULL AST rules.

This module intentionally models only the structured C control-flow constructs
needed by the memory-safety rules.  It is used only when pycparser produced a
real AST; the existing lexical fallback remains available otherwise.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .ast_analyzer import _extract_identifiers_from_ast, _format_pycparser_expr, _PRELUDE_LINE_COUNT


class Nullness(Enum):
    NULL = "NULL"
    NON_NULL = "NON_NULL"
    MAYBE_NULL = "MAYBE_NULL"
    UNKNOWN = "UNKNOWN"


class Initialization(Enum):
    UNINITIALIZED = "UNINITIALIZED"
    INITIALIZED = "INITIALIZED"
    MAYBE_INITIALIZED = "MAYBE_INITIALIZED"


class Allocation(Enum):
    NOT_ALLOCATED = "NOT_ALLOCATED"
    ALLOCATED = "ALLOCATED"
    MAYBE_ALLOCATED = "MAYBE_ALLOCATED"
    FREED = "FREED"
    MAYBE_FREED = "MAYBE_FREED"


@dataclass
class FunctionSummary:
    freed_params: Set[int] = field(default_factory=set)
    return_nullness: Nullness = Nullness.UNKNOWN
    returns_allocation: bool = False
    is_unknown: bool = False


@dataclass
class VariableFacts:
    nullness: Nullness = Nullness.UNKNOWN
    initialization: Initialization = Initialization.UNINITIALIZED
    allocation: Allocation = Allocation.NOT_ALLOCATED


@dataclass
class BasicBlock:
    block_id: int
    nodes: List["CFGEvent"] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)  # list of block_ids
    successors: List[int] = field(default_factory=list)    # list of block_ids
    edge_facts: Dict[int, Tuple[Set[str], Set[str]]] = field(default_factory=dict)  # succ block_id -> (add, remove)

    # In and Out facts at block entry and block exit
    nullness_in: Dict[str, Nullness] = field(default_factory=dict)
    nullness_out: Dict[str, Nullness] = field(default_factory=dict)

    init_in: Dict[str, Initialization] = field(default_factory=dict)
    init_out: Dict[str, Initialization] = field(default_factory=dict)

    alloc_in: Dict[str, Allocation] = field(default_factory=dict)
    alloc_out: Dict[str, Allocation] = field(default_factory=dict)

    # Alias and location lifecycle tracking facts
    loc_state_in: Dict[str, Allocation] = field(default_factory=dict)
    loc_state_out: Dict[str, Allocation] = field(default_factory=dict)
    loc_map_in: Dict[str, Set[str]] = field(default_factory=dict)
    loc_map_out: Dict[str, Set[str]] = field(default_factory=dict)


@dataclass
class CFGEvent:
    node_id: int
    kind: str
    line_number: int
    expr_str: str = ""
    reads: Set[str] = field(default_factory=set)
    writes: Set[str] = field(default_factory=set)
    null_writes: Set[str] = field(default_factory=set)
    maybe_null_writes: Set[str] = field(default_factory=set)
    freed: Set[str] = field(default_factory=set)
    allocated: Set[str] = field(default_factory=set)
    derefs: Set[str] = field(default_factory=set)
    asserted: Set[str] = field(default_factory=set)
    alias_writes: Dict[str, str] = field(default_factory=dict)
    realloc_inputs: Set[str] = field(default_factory=set)
    realloc_bindings: Dict[str, str] = field(default_factory=dict)
    successors: List[int] = field(default_factory=list)


class StructuredCFG:
    def __init__(self) -> None:
        self.nodes: Dict[int, CFGEvent] = {}
        self.edge_facts: Dict[Tuple[int, int], Tuple[Set[str], Set[str]]] = {}
        self.entry: Optional[int] = None
        self._next_id = 0
        self.blocks: Dict[int, BasicBlock] = {}
        self.node_to_block: Dict[int, int] = {}

    def add_node(self, node: CFGEvent) -> int:
        self.nodes[node.node_id] = node
        return node.node_id

    def new_node(self, kind: str, ast_node=None, **kwargs) -> int:
        self._next_id += 1
        line = 1
        if ast_node is not None and getattr(ast_node, "coord", None):
            line = max(1, ast_node.coord.line - _PRELUDE_LINE_COUNT)
        node = CFGEvent(node_id=self._next_id, kind=kind, line_number=line, **kwargs)
        setattr(node, "_ast_node", ast_node)
        return self.add_node(node)

    def connect(self, src: int, dst: Optional[int], *, add: Iterable[str] = (), remove: Iterable[str] = ()) -> None:
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
                if len(node.successors) > 1:
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

                    edge_fact = self.edge_facts.get((last_node.node_id, succ_node_id))
                    if edge_fact:
                        block.edge_facts[succ_block.block_id] = edge_fact

        return self.blocks

    def analyze_dataflow(self, initial_nonnull: Optional[Set[str]] = None,
                         initial_initialized: Optional[Set[str]] = None,
                         all_vars: Optional[Set[str]] = None) -> None:
        """Run fixed-point dataflow analysis across basic blocks for Nullness, Initialization, and Allocation facts."""
        if not self.blocks:
            self.build_basic_blocks()
        if not self.blocks:
            return

        if all_vars is None:
            all_vars = set()
            for node in self.nodes.values():
                all_vars.update(node.reads)
                all_vars.update(node.writes)
                all_vars.update(node.allocated)
                all_vars.update(node.freed)
                all_vars.update(node.asserted)
                all_vars.update(node.derefs)
                all_vars.update(node.alias_writes.keys())
                all_vars.update(node.alias_writes.values())

        init_nonnull = set(initial_nonnull) if initial_nonnull else set()
        init_initialized = set(initial_initialized) if initial_initialized else set()

        self.realloc_records: Dict[str, Tuple[str, str, Set[str], Dict[str, Allocation], bool]] = {}

        for block in self.blocks.values():
            block.nullness_in = {}
            block.nullness_out = {}
            block.init_in = {}
            block.init_out = {}
            block.alloc_in = {}
            block.alloc_out = {}
            block.loc_state_in = {}
            block.loc_state_out = {}
            block.loc_map_in = {}
            block.loc_map_out = {}

        entry_block_id = self.node_to_block.get(self.entry) if self.entry else min(self.blocks.keys())

        reachable_blocks: Set[int] = set()
        if entry_block_id in self.blocks:
            queue = [entry_block_id]
            while queue:
                b_id = queue.pop(0)
                if b_id in reachable_blocks:
                    continue
                reachable_blocks.add(b_id)
                for succ in self.blocks[b_id].successors:
                    if succ not in reachable_blocks:
                        queue.append(succ)

        entry_block = self.blocks.get(entry_block_id)

        if entry_block:
            for v in all_vars:
                entry_block.nullness_in[v] = Nullness.NON_NULL if v in init_nonnull else Nullness.UNKNOWN
                entry_block.init_in[v] = Initialization.INITIALIZED if v in init_initialized else Initialization.UNINITIALIZED
                entry_block.alloc_in[v] = Allocation.NOT_ALLOCATED
                loc_id = f"var_{v}"
                entry_block.loc_map_in[v] = {loc_id}
                entry_block.loc_state_in[loc_id] = Allocation.NOT_ALLOCATED

        worklist = [entry_block_id] if entry_block_id in reachable_blocks else []

        while worklist:
            b_id = worklist.pop(0)
            if b_id not in reachable_blocks:
                continue
            block = self.blocks[b_id]

            curr_null = dict(block.nullness_in)
            curr_init = dict(block.init_in)
            curr_loc_state = dict(block.loc_state_in)
            curr_loc_map = {v: set(locs) for v, locs in block.loc_map_in.items()}

            for node in block.nodes:
                if getattr(node, "realloc_bindings", None):
                    for target_var, input_ptr in node.realloc_bindings.items():
                        input_locs = set(curr_loc_map.get(input_ptr, set()))
                        if not input_locs:
                            input_locs = {f"var_{input_ptr}"}
                        pre_states = {loc: curr_loc_state.get(loc, Allocation.NOT_ALLOCATED) for loc in input_locs}
                        base_loc_id = f"alloc_{node.node_id}_{target_var}"
                        new_loc_id = base_loc_id
                        if curr_loc_state.get(base_loc_id) in (Allocation.FREED, Allocation.MAYBE_FREED) or any(other != target_var and base_loc_id in curr_loc_map.get(other, set()) for other in all_vars):
                            new_loc_id = f"alloc_{node.node_id}_{target_var}_fresh"

                        size_is_zero = False
                        ast_node = getattr(node, "_ast_node", None)
                        if ast_node is not None:
                            val_call = _find_value_producing_call(getattr(ast_node, "init", None) or getattr(ast_node, "rvalue", None))
                            if val_call and len(val_call[1]) >= 2:
                                size_is_zero = _is_nullish(val_call[1][1])

                        self.realloc_records[new_loc_id] = (target_var, input_ptr, input_locs, pre_states, size_is_zero)

                for ptr in node.realloc_inputs:
                    locs = curr_loc_map.get(ptr, set())
                    for loc in locs:
                        curr_loc_state[loc] = meet_allocation(curr_loc_state.get(loc, Allocation.NOT_ALLOCATED), Allocation.MAYBE_FREED)

                for v in node.allocated:
                    base_loc_id = f"alloc_{node.node_id}_{v}"
                    loc_id = base_loc_id
                    if curr_loc_state.get(base_loc_id) in (Allocation.FREED, Allocation.MAYBE_FREED) or any(other != v and base_loc_id in curr_loc_map.get(other, set()) for other in all_vars):
                        loc_id = f"alloc_{node.node_id}_{v}_fresh"
                    curr_loc_state[loc_id] = Allocation.ALLOCATED
                    curr_loc_map[v] = {loc_id}
                    curr_null[v] = Nullness.MAYBE_NULL
                    curr_init[v] = Initialization.INITIALIZED

                for v in node.freed:
                    locs = curr_loc_map.get(v, set())
                    if not locs:
                        loc_id = f"var_{v}"
                        locs = {loc_id}
                        curr_loc_map[v] = locs
                    for loc in locs:
                        curr_loc_state[loc] = Allocation.FREED

                for v in node.writes:
                    curr_init[v] = Initialization.INITIALIZED
                    if v not in node.allocated:
                        if v in node.alias_writes:
                            rhs_var = node.alias_writes[v]
                            rhs_locs = curr_loc_map.get(rhs_var, set())
                            if not rhs_locs:
                                loc_id = f"var_{rhs_var}"
                                rhs_locs = {loc_id}
                                curr_loc_state[loc_id] = Allocation.NOT_ALLOCATED
                                curr_loc_map[rhs_var] = rhs_locs
                            curr_loc_map[v] = set(rhs_locs)
                            curr_null[v] = curr_null.get(rhs_var, Nullness.UNKNOWN)
                        else:
                            loc_id = f"write_{node.node_id}_{v}"
                            curr_loc_state[loc_id] = Allocation.NOT_ALLOCATED
                            curr_loc_map[v] = {loc_id}
                            if v in node.null_writes:
                                curr_null[v] = Nullness.NULL
                            elif v in node.maybe_null_writes:
                                curr_null[v] = Nullness.MAYBE_NULL
                            else:
                                curr_null[v] = Nullness.UNKNOWN

                for v in node.asserted:
                    curr_null[v] = Nullness.NON_NULL
                for v in node.derefs:
                    curr_null[v] = Nullness.NON_NULL

            block.nullness_out = curr_null
            block.init_out = curr_init
            block.loc_state_out = curr_loc_state
            block.loc_map_out = curr_loc_map

            curr_alloc: Dict[str, Allocation] = {}
            for v in all_vars:
                locs = curr_loc_map.get(v, set())
                if not locs:
                    curr_alloc[v] = Allocation.NOT_ALLOCATED
                else:
                    v_alloc: Optional[Allocation] = None
                    for loc in locs:
                        loc_st = curr_loc_state.get(loc, Allocation.NOT_ALLOCATED)
                        v_alloc = loc_st if v_alloc is None else meet_allocation(v_alloc, loc_st)
                    curr_alloc[v] = v_alloc if v_alloc is not None else Allocation.NOT_ALLOCATED
            block.alloc_out = curr_alloc

            for succ_id in block.successors:
                if succ_id not in reachable_blocks:
                    continue
                succ_block = self.blocks[succ_id]
                edge_fact = block.edge_facts.get(succ_id, (set(), set()))
                add_nonnull, remove_nonnull = edge_fact

                edge_null = dict(curr_null)
                for v in add_nonnull:
                    edge_null[v] = Nullness.NON_NULL
                for v in remove_nonnull:
                    edge_null[v] = Nullness.NULL

                changed = False

                for v in all_vars:
                    # Nullness
                    e_null = edge_null.get(v, Nullness.UNKNOWN)
                    if v not in succ_block.nullness_in:
                        new_null = e_null
                    else:
                        new_null = meet_nullness(succ_block.nullness_in[v], e_null)
                    if succ_block.nullness_in.get(v) != new_null:
                        succ_block.nullness_in[v] = new_null
                        changed = True

                    # Init
                    e_init = curr_init.get(v, Initialization.UNINITIALIZED)
                    if v not in succ_block.init_in:
                        new_init = e_init
                    else:
                        new_init = meet_initialization(succ_block.init_in[v], e_init)
                    if succ_block.init_in.get(v) != new_init:
                        succ_block.init_in[v] = new_init
                        changed = True

                    # Loc Map
                    out_map = curr_loc_map.get(v, set())
                    if v not in succ_block.loc_map_in:
                        new_map = set(out_map)
                    else:
                        new_map = succ_block.loc_map_in[v].union(out_map)
                    if succ_block.loc_map_in.get(v) != new_map:
                        succ_block.loc_map_in[v] = new_map
                        changed = True

                # Loc State
                edge_loc_state = dict(curr_loc_state)
                for new_loc_id, (target_var, input_ptr, input_locs, pre_states, size_is_zero) in self.realloc_records.items():
                    if new_loc_id in curr_loc_map.get(target_var, set()):
                        t_null = edge_null.get(target_var, Nullness.UNKNOWN)
                        if t_null == Nullness.NON_NULL:
                            for loc in input_locs:
                                if pre_states.get(loc) in (Allocation.ALLOCATED, Allocation.MAYBE_ALLOCATED, Allocation.MAYBE_FREED):
                                    edge_loc_state[loc] = Allocation.FREED
                            edge_loc_state[new_loc_id] = Allocation.ALLOCATED
                        elif t_null == Nullness.NULL:
                            for loc in input_locs:
                                if size_is_zero:
                                    edge_loc_state[loc] = Allocation.MAYBE_FREED
                                else:
                                    edge_loc_state[loc] = pre_states.get(loc, Allocation.NOT_ALLOCATED)
                            edge_loc_state[new_loc_id] = Allocation.NOT_ALLOCATED

                all_loc_ids = set(edge_loc_state.keys()).union(succ_block.loc_state_in.keys())
                for loc in all_loc_ids:
                    e_loc_st = edge_loc_state.get(loc, Allocation.NOT_ALLOCATED)
                    if loc not in succ_block.loc_state_in:
                        new_loc_st = e_loc_st
                    else:
                        new_loc_st = meet_allocation(succ_block.loc_state_in[loc], e_loc_st)
                    if succ_block.loc_state_in.get(loc) != new_loc_st:
                        succ_block.loc_state_in[loc] = new_loc_st
                        changed = True

                # Recompute succ_block.alloc_in from loc_map_in and loc_state_in
                for v in all_vars:
                    locs = succ_block.loc_map_in.get(v, set())
                    if not locs:
                        new_alloc = Allocation.NOT_ALLOCATED
                    else:
                        v_alloc = None
                        for loc in locs:
                            l_st = succ_block.loc_state_in.get(loc, Allocation.NOT_ALLOCATED)
                            v_alloc = l_st if v_alloc is None else meet_allocation(v_alloc, l_st)
                        new_alloc = v_alloc if v_alloc is not None else Allocation.NOT_ALLOCATED
                    if succ_block.alloc_in.get(v) != new_alloc:
                        succ_block.alloc_in[v] = new_alloc
                        changed = True

                if changed and succ_id not in worklist:
                    worklist.append(succ_id)

        self._compute_node_level_facts(all_vars)

    def _compute_node_level_facts(self, all_vars: Set[str]) -> None:
        self.node_facts: Dict[int, Dict[str, VariableFacts]] = {}
        self.node_loc_maps: Dict[int, Dict[str, Set[str]]] = {}
        for block in self.blocks.values():
            curr_null = dict(block.nullness_in)
            curr_init = dict(block.init_in)
            curr_loc_state = dict(block.loc_state_in)
            curr_loc_map = {v: set(locs) for v, locs in block.loc_map_in.items()}

            for node in block.nodes:
                if hasattr(self, "realloc_records"):
                    for new_loc_id, (target_var, input_ptr, input_locs, pre_states, size_is_zero) in self.realloc_records.items():
                        if new_loc_id in curr_loc_map.get(target_var, set()):
                            t_null = curr_null.get(target_var, Nullness.UNKNOWN)
                            if t_null == Nullness.NON_NULL:
                                for loc in input_locs:
                                    if pre_states.get(loc) in (Allocation.ALLOCATED, Allocation.MAYBE_ALLOCATED, Allocation.MAYBE_FREED):
                                        curr_loc_state[loc] = Allocation.FREED
                                curr_loc_state[new_loc_id] = Allocation.ALLOCATED
                            elif t_null == Nullness.NULL:
                                for loc in input_locs:
                                    if size_is_zero:
                                        curr_loc_state[loc] = Allocation.MAYBE_FREED
                                    else:
                                        curr_loc_state[loc] = pre_states.get(loc, Allocation.NOT_ALLOCATED)
                                curr_loc_state[new_loc_id] = Allocation.NOT_ALLOCATED

                curr_node_alloc: Dict[str, Allocation] = {}
                for v in all_vars:
                    locs = curr_loc_map.get(v, set())
                    if not locs:
                        curr_node_alloc[v] = Allocation.NOT_ALLOCATED
                    else:
                        v_alloc: Optional[Allocation] = None
                        for loc in locs:
                            l_st = curr_loc_state.get(loc, Allocation.NOT_ALLOCATED)
                            v_alloc = l_st if v_alloc is None else meet_allocation(v_alloc, l_st)
                        curr_node_alloc[v] = v_alloc if v_alloc is not None else Allocation.NOT_ALLOCATED

                self.node_facts[node.node_id] = {
                    v: VariableFacts(
                        nullness=curr_null.get(v, Nullness.UNKNOWN),
                        initialization=curr_init.get(v, Initialization.UNINITIALIZED),
                        allocation=curr_node_alloc.get(v, Allocation.NOT_ALLOCATED),
                    )
                    for v in all_vars
                }
                self.node_loc_maps[node.node_id] = {
                    v: set(locs) for v, locs in curr_loc_map.items()
                }

                if getattr(node, "realloc_bindings", None):
                    for target_var, input_ptr in node.realloc_bindings.items():
                        input_locs = set(curr_loc_map.get(input_ptr, set()))
                        if not input_locs:
                            input_locs = {f"var_{input_ptr}"}
                        pre_states = {loc: curr_loc_state.get(loc, Allocation.NOT_ALLOCATED) for loc in input_locs}
                        base_loc_id = f"alloc_{node.node_id}_{target_var}"
                        new_loc_id = base_loc_id
                        if curr_loc_state.get(base_loc_id) in (Allocation.FREED, Allocation.MAYBE_FREED) or any(other != target_var and base_loc_id in curr_loc_map.get(other, set()) for other in all_vars):
                            new_loc_id = f"alloc_{node.node_id}_{target_var}_fresh"
                        size_is_zero = False
                        ast_node = getattr(node, "_ast_node", None)
                        if ast_node is not None:
                            val_call = _find_value_producing_call(getattr(ast_node, "init", None) or getattr(ast_node, "rvalue", None))
                            if val_call and len(val_call[1]) >= 2:
                                size_is_zero = _is_nullish(val_call[1][1])
                        if hasattr(self, "realloc_records"):
                            self.realloc_records[new_loc_id] = (target_var, input_ptr, input_locs, pre_states, size_is_zero)

                for ptr in node.realloc_inputs:
                    locs = curr_loc_map.get(ptr, set())
                    for loc in locs:
                        curr_loc_state[loc] = meet_allocation(curr_loc_state.get(loc, Allocation.NOT_ALLOCATED), Allocation.MAYBE_FREED)

                for v in node.allocated:
                    base_loc_id = f"alloc_{node.node_id}_{v}"
                    loc_id = base_loc_id
                    if curr_loc_state.get(base_loc_id) in (Allocation.FREED, Allocation.MAYBE_FREED) or any(other != v and base_loc_id in curr_loc_map.get(other, set()) for other in all_vars):
                        loc_id = f"alloc_{node.node_id}_{v}_fresh"
                    curr_loc_state[loc_id] = Allocation.ALLOCATED
                    curr_loc_map[v] = {loc_id}
                    curr_null[v] = Nullness.MAYBE_NULL
                    curr_init[v] = Initialization.INITIALIZED

                for v in node.freed:
                    locs = curr_loc_map.get(v, set())
                    if not locs:
                        loc_id = f"var_{v}"
                        locs = {loc_id}
                        curr_loc_map[v] = locs
                    for loc in locs:
                        curr_loc_state[loc] = Allocation.FREED

                for v in node.writes:
                    curr_init[v] = Initialization.INITIALIZED
                    if v not in node.allocated:
                        if v in node.alias_writes:
                            rhs_var = node.alias_writes[v]
                            rhs_locs = curr_loc_map.get(rhs_var, set())
                            if not rhs_locs:
                                loc_id = f"var_{rhs_var}"
                                rhs_locs = {loc_id}
                                curr_loc_state[loc_id] = Allocation.NOT_ALLOCATED
                                curr_loc_map[rhs_var] = rhs_locs
                            curr_loc_map[v] = set(rhs_locs)
                            curr_null[v] = curr_null.get(rhs_var, Nullness.UNKNOWN)
                        else:
                            loc_id = f"write_{node.node_id}_{v}"
                            curr_loc_state[loc_id] = Allocation.NOT_ALLOCATED
                            curr_loc_map[v] = {loc_id}
                            if v in node.null_writes:
                                curr_null[v] = Nullness.NULL
                            elif v in node.maybe_null_writes:
                                curr_null[v] = Nullness.MAYBE_NULL
                            else:
                                curr_null[v] = Nullness.UNKNOWN

                for v in node.asserted:
                    curr_null[v] = Nullness.NON_NULL
                for v in node.derefs:
                    curr_null[v] = Nullness.NON_NULL

    def get_facts_at_node(self, node_id: int) -> Dict[str, VariableFacts]:
        if not hasattr(self, "node_facts"):
            self.analyze_dataflow()
        return self.node_facts.get(node_id, {})

    def query_nullness(self, var_name: str, node_id: int) -> Nullness:
        facts = self.get_facts_at_node(node_id)
        if var_name in facts:
            return facts[var_name].nullness
        return Nullness.UNKNOWN

    def query_initialization(self, var_name: str, node_id: int) -> Initialization:
        facts = self.get_facts_at_node(node_id)
        if var_name in facts:
            return facts[var_name].initialization
        return Initialization.UNINITIALIZED

    def query_allocation(self, var_name: str, node_id: int) -> Allocation:
        facts = self.get_facts_at_node(node_id)
        if var_name in facts:
            return facts[var_name].allocation
        return Allocation.NOT_ALLOCATED

    def get_loc_map_at_node(self, node_id: int) -> Dict[str, Set[str]]:
        if not hasattr(self, "node_loc_maps"):
            self.analyze_dataflow()
        return self.node_loc_maps.get(node_id, {})


def meet_nullness(a: Nullness, b: Nullness) -> Nullness:
    if a == Nullness.UNKNOWN:
        return b
    if b == Nullness.UNKNOWN:
        return a
    if a == b:
        return a
    if (a == Nullness.NON_NULL and b == Nullness.NULL) or (a == Nullness.NULL and b == Nullness.NON_NULL):
        return Nullness.MAYBE_NULL
    if a == Nullness.MAYBE_NULL or b == Nullness.MAYBE_NULL:
        return Nullness.MAYBE_NULL
    return Nullness.UNKNOWN


def meet_initialization(a: Initialization, b: Initialization) -> Initialization:
    if a == b:
        return a
    if a == Initialization.MAYBE_INITIALIZED or b == Initialization.MAYBE_INITIALIZED:
        return Initialization.MAYBE_INITIALIZED
    if (a == Initialization.INITIALIZED and b == Initialization.UNINITIALIZED) or \
       (a == Initialization.UNINITIALIZED and b == Initialization.INITIALIZED):
        return Initialization.MAYBE_INITIALIZED
    return a


def meet_allocation(a: Allocation, b: Allocation) -> Allocation:
    if a == b:
        return a
    if a == Allocation.MAYBE_FREED or b == Allocation.MAYBE_FREED:
        return Allocation.MAYBE_FREED
    if a == Allocation.FREED or b == Allocation.FREED:
        return Allocation.MAYBE_FREED
    if a == Allocation.MAYBE_ALLOCATED or b == Allocation.MAYBE_ALLOCATED:
        return Allocation.MAYBE_ALLOCATED
    if (a == Allocation.ALLOCATED and b == Allocation.NOT_ALLOCATED) or \
       (a == Allocation.NOT_ALLOCATED and b == Allocation.ALLOCATED):
        return Allocation.MAYBE_ALLOCATED
    return Allocation.NOT_ALLOCATED


def _ids(node) -> Set[str]:
    return _extract_identifiers_from_ast(node)


def _call_names(node) -> Set[str]:
    names: Set[str] = set()
    if node is None:
        return names
    if type(node).__name__ == "FuncCall":
        names.add(_format_pycparser_expr(node.name))
    for _, child in node.children():
        names.update(_call_names(child))
    return names


def _call_args(node, callee: str):
    if node is None:
        return []
    if type(node).__name__ == "FuncCall" and _format_pycparser_expr(node.name) == callee:
        return list(getattr(node.args, "exprs", []) or [])
    for _, child in node.children():
        result = _call_args(child, callee)
        if result:
            return result
    return []


def _freed_vars(node, dealloc_funcs: Optional[Set[str]] = None) -> Set[str]:
    freed: Set[str] = set()
    funcs = dealloc_funcs if dealloc_funcs is not None else {"free", "cfree", "vfree"}
    for callee in funcs:
        for arg in _call_args_all(node, callee):
            arg_unwrapped = _unwrap_cast(arg)
            if arg_unwrapped is not None and type(arg_unwrapped).__name__ == "ID":
                freed.add(str(arg_unwrapped.name))
    return freed


def _call_args_all(node, callee: str):
    result = []
    if node is None:
        return result
    if type(node).__name__ == "FuncCall" and _format_pycparser_expr(node.name) == callee:
        result.extend(getattr(node.args, "exprs", []) or [])
    for _, child in node.children():
        result.extend(_call_args_all(child, callee))
    return result


def _unwrap_cast(node):
    while node is not None and type(node).__name__ in {"Cast", "ExprList"}:
        if type(node).__name__ == "Cast":
            node = node.expr
        elif type(node).__name__ == "ExprList":
            node = node.exprs[-1] if getattr(node, "exprs", None) else None
    return node


def _deref_vars(node) -> Set[str]:
    result: Set[str] = set()
    if node is None:
        return result
    kind = type(node).__name__
    if kind == "UnaryOp" and getattr(node, "op", None) == "*":
        inner = _unwrap_cast(node.expr)
        if inner is not None and type(inner).__name__ == "ID":
            result.add(str(inner.name))
    elif kind == "ArrayRef":
        inner = _unwrap_cast(node.name)
        if inner is not None and type(inner).__name__ == "ID":
            result.add(str(inner.name))
    elif kind == "StructRef":
        inner = _unwrap_cast(node.name)
        if inner is not None and type(inner).__name__ == "ID":
            result.add(str(inner.name))
    for _, child in node.children():
        result.update(_deref_vars(child))
    return result


def _assignment_target(node) -> Set[str]:
    if node is None:
        return set()
    inner = _unwrap_cast(node)
    if inner is not None and type(inner).__name__ == "ID":
        return {str(inner.name)}
    return set()


def _is_nullish(node) -> bool:
    if node is None:
        return False
    inner = _unwrap_cast(node)
    if inner is None:
        return False
    kind = type(inner).__name__
    if kind == "ID":
        return str(inner.name) in {"NULL", "nullptr"}
    if kind == "Cast":
        return _is_nullish(inner.expr)
    if kind == "UnaryOp" and getattr(inner, "op", None) in {"+", "-"}:
        return _is_nullish(inner.expr)
    return kind == "Constant" and str(getattr(inner, "value", "")) in {"0", "0x0", "0L", "0UL", "0LL", "0ULL"}


def _simple_null_facts(cond) -> Tuple[Set[str], Set[str]]:
    """Return (true-edge nonnull facts, false-edge nonnull facts)."""
    if cond is None:
        return set(), set()
    cond_unwrapped = _unwrap_cast(cond)
    if cond_unwrapped is None:
        return set(), set()
    kind = type(cond_unwrapped).__name__
    if kind == "ID":
        return {str(cond_unwrapped.name)}, set()
    if kind == "UnaryOp" and getattr(cond_unwrapped, "op", None) == "!":
        inner = _unwrap_cast(cond_unwrapped.expr)
        if inner is not None and type(inner).__name__ == "ID":
            return set(), {str(inner.name)}
    if kind == "BinaryOp":
        op = getattr(cond_unwrapped, "op", None)
        if op in {"==", "!="}:
            lhs = _unwrap_cast(cond_unwrapped.left)
            rhs = _unwrap_cast(cond_unwrapped.right)
            if lhs is not None and rhs is not None:
                if type(lhs).__name__ == "ID" and _is_nullish(rhs):
                    var = str(lhs.name)
                elif type(rhs).__name__ == "ID" and _is_nullish(lhs):
                    var = str(rhs.name)
                else:
                    return set(), set()
                if op == "!=":
                    return {var}, set()
                return set(), {var}
        elif op == "||":
            l_t, l_f = _simple_null_facts(cond_unwrapped.left)
            r_t, r_f = _simple_null_facts(cond_unwrapped.right)
            return l_t.intersection(r_t), l_f.union(r_f)
        elif op == "&&":
            l_t, l_f = _simple_null_facts(cond_unwrapped.left)
            r_t, r_f = _simple_null_facts(cond_unwrapped.right)
            return l_t.union(r_t), l_f.intersection(r_f)
    return set(), set()


def _process_call_effects(call_node, target_var: Optional[str], summaries: Optional[Dict[str, FunctionSummary]], alloc_set: Set[str], realloc_set: Set[str], freed: Set[str], allocated: Set[str], null_writes: Set[str], maybe_null_writes: Set[str], realloc_inputs: Set[str], realloc_bindings: Dict[str, str], is_value_producing: bool = False):
    """Applies summary effects for a single FuncCall node."""
    callee = _format_pycparser_expr(call_node.name)
    args = list(getattr(call_node.args, "exprs", []) or []) if call_node.args else []

    # Check builtin or custom summary
    summary = summaries.get(callee) if summaries else None

    # Handle parameter deallocation (freed arguments)
    if summary and summary.freed_params:
        for p_idx in summary.freed_params:
            if p_idx < len(args):
                arg_unwrapped = _unwrap_cast(args[p_idx])
                if arg_unwrapped is not None and type(arg_unwrapped).__name__ == "ID":
                    freed.add(str(arg_unwrapped.name))

    # Handle allocation / return effects
    if target_var:
        if callee in alloc_set or (summary and summary.returns_allocation):
            allocated.add(target_var)
            if callee in realloc_set:
                if args:
                    arg1 = _unwrap_cast(args[0])
                    if type(arg1).__name__ == "ID":
                        input_ptr = str(arg1.name)
                        realloc_inputs.add(input_ptr)
                        if is_value_producing:
                            realloc_bindings[target_var] = input_ptr
        elif summary:
            if summary.return_nullness == Nullness.NULL:
                null_writes.add(target_var)
            elif summary.return_nullness == Nullness.MAYBE_NULL:
                maybe_null_writes.add(target_var)
        elif callee not in alloc_set:
            # Unknown callee returning a pointer: conservative handling (could return NULL or MAYBE_NULL if assigned)
            pass


def _find_ternary_op(node):
    if node is None:
        return None
    kind = type(node).__name__
    if kind == "TernaryOp":
        return node
    for _, child in node.children():
        res = _find_ternary_op(child)
        if res is not None:
            return res
    return None


def _replace_ast_node(tree, target, replacement):
    from pycparser import c_ast
    if tree is target:
        return replacement
    if tree is None:
        return None
    import copy
    tree_copy = copy.copy(tree)
    slots = set()
    for cls in type(tree_copy).__mro__:
        for slot in getattr(cls, '__slots__', ()):
            slots.add(slot)
    for attr in slots:
        val = getattr(tree_copy, attr, None)
        if isinstance(val, list):
            new_list = [_replace_ast_node(item, target, replacement) if isinstance(item, c_ast.Node) else item for item in val]
            setattr(tree_copy, attr, new_list)
        elif isinstance(val, c_ast.Node):
            setattr(tree_copy, attr, _replace_ast_node(val, target, replacement))
    return tree_copy


def _find_value_producing_call(node) -> Optional[Tuple[str, list]]:
    unwrapped = _unwrap_cast(node)
    if unwrapped is not None and type(unwrapped).__name__ == "FuncCall":
        callee = _format_pycparser_expr(unwrapped.name)
        args = list(getattr(unwrapped.args, "exprs", []) or []) if unwrapped.args else []
        return callee, args
    return None


def _event_payload(ast_node, alloc_funcs: Optional[Set[str]] = None, dealloc_funcs: Optional[Set[str]] = None, realloc_funcs: Optional[Set[str]] = None, summaries: Optional[Dict[str, FunctionSummary]] = None) -> Tuple[str, Set[str], Set[str], Set[str], Set[str], Set[str], Set[str], Set[str], Set[str], Dict[str, str], Set[str], Dict[str, str]]:
    """kind, reads, writes, null_writes, maybe_null_writes, freed, allocated, derefs, asserted, alias_writes, realloc_inputs, realloc_bindings for an executable AST node."""
    kind = type(ast_node).__name__
    reads: Set[str] = set()
    writes: Set[str] = set()
    null_writes: Set[str] = set()
    maybe_null_writes: Set[str] = set()
    freed: Set[str] = _freed_vars(ast_node, dealloc_funcs=dealloc_funcs)
    allocated: Set[str] = set()
    derefs = _deref_vars(ast_node)
    alias_writes: Dict[str, str] = {}
    realloc_inputs: Set[str] = set()
    realloc_bindings: Dict[str, str] = {}
    expr = _format_pycparser_expr(ast_node)

    alloc_set = alloc_funcs if alloc_funcs is not None else {"malloc", "calloc", "realloc", "aligned_alloc"}
    realloc_set = realloc_funcs if realloc_funcs is not None else {"realloc"}

    # Process call summaries for function calls in expressions
    if summaries:
        def visit_calls(n, curr_target_var=None, is_value_producing=False):
            if n is None:
                return
            n_kind = type(n).__name__
            if n_kind == "FuncCall":
                _process_call_effects(n, curr_target_var, summaries, alloc_set, realloc_set, freed, allocated, null_writes, maybe_null_writes, realloc_inputs, realloc_bindings, is_value_producing=is_value_producing)
                for _, child in n.children():
                    visit_calls(child, curr_target_var=None, is_value_producing=False)
            else:
                unwrapped = _unwrap_cast(n)
                for _, child in n.children():
                    child_is_vp = is_value_producing and (child is unwrapped)
                    visit_calls(child, curr_target_var=curr_target_var, is_value_producing=child_is_vp)

        if kind == "Decl" and ast_node.name and ast_node.init:
            visit_calls(ast_node.init, curr_target_var=str(ast_node.name), is_value_producing=True)
        elif kind == "Assignment":
            lhs_target = list(_assignment_target(ast_node.lvalue))
            t_var = lhs_target[0] if lhs_target else None
            visit_calls(ast_node.rvalue, curr_target_var=t_var, is_value_producing=True)
        elif kind == "FuncCall":
            visit_calls(ast_node, curr_target_var=None, is_value_producing=False)

    if kind == "Decl":
        if ast_node.init is not None:
            reads = _ids(ast_node.init)
            writes = {str(ast_node.name)} if ast_node.name else set()
            if _is_nullish(ast_node.init):
                null_writes.update(writes)

            val_call = _find_value_producing_call(ast_node.init)
            if val_call is not None:
                callee_fn, c_args = val_call
                if callee_fn in realloc_set and c_args:
                    arg1 = _unwrap_cast(c_args[0])
                    if type(arg1).__name__ == "ID":
                        input_ptr = str(arg1.name)
                        realloc_inputs.add(input_ptr)
                        if ast_node.name:
                            realloc_bindings[str(ast_node.name)] = input_ptr

            for call_name in _call_names(ast_node.init):
                if call_name in alloc_set or (summaries and summaries.get(call_name) and summaries[call_name].returns_allocation):
                    if ast_node.name:
                        allocated.add(str(ast_node.name))
                    if call_name in realloc_set:
                        args = _call_args(ast_node.init, call_name)
                        if args:
                            arg1 = _unwrap_cast(args[0])
                            if type(arg1).__name__ == "ID":
                                realloc_inputs.add(str(arg1.name))
                    break
            if not allocated and ast_node.name and not _is_nullish(ast_node.init):
                rhs_unwrapped = _unwrap_cast(ast_node.init)
                if type(rhs_unwrapped).__name__ == "ID":
                    rhs_var = str(rhs_unwrapped.name)
                    if rhs_var not in alloc_set and rhs_var not in {"NULL", "nullptr"}:
                        alias_writes[str(ast_node.name)] = rhs_var
    elif kind == "Assignment":
        reads = _ids(ast_node.rvalue)
        writes = _assignment_target(ast_node.lvalue)
        if _is_nullish(ast_node.rvalue):
            null_writes.update(writes)

        val_call = _find_value_producing_call(ast_node.rvalue)
        if val_call is not None:
            callee_fn, c_args = val_call
            if callee_fn in realloc_set and c_args:
                arg1 = _unwrap_cast(c_args[0])
                if type(arg1).__name__ == "ID":
                    input_ptr = str(arg1.name)
                    realloc_inputs.add(input_ptr)
                    for w in writes:
                        realloc_bindings[w] = input_ptr

        for call_name in _call_names(ast_node.rvalue):
            if call_name in alloc_set or (summaries and summaries.get(call_name) and summaries[call_name].returns_allocation):
                allocated.update(writes)
                if call_name in realloc_set:
                    args = _call_args(ast_node.rvalue, call_name)
                    if args:
                        arg1 = _unwrap_cast(args[0])
                        if type(arg1).__name__ == "ID":
                            realloc_inputs.add(str(arg1.name))
                break
        if not allocated and writes and getattr(ast_node, "op", "=") == "=" and not _is_nullish(ast_node.rvalue):
            lhs_unwrapped = _unwrap_cast(ast_node.lvalue)
            rhs_unwrapped = _unwrap_cast(ast_node.rvalue)
            if lhs_unwrapped is not None and type(lhs_unwrapped).__name__ == "ID" and rhs_unwrapped is not None and type(rhs_unwrapped).__name__ == "ID":
                lhs_var = str(lhs_unwrapped.name)
                rhs_var = str(rhs_unwrapped.name)
                if rhs_var not in alloc_set and rhs_var not in {"NULL", "nullptr"}:
                    alias_writes[lhs_var] = rhs_var
    elif kind == "FuncCall":
        reads = _ids(ast_node.args) if ast_node.args is not None else set()
    elif kind == "Return":
        reads = _ids(ast_node.expr) if ast_node.expr is not None else set()
    elif kind in {"Label", "Goto"}:
        return kind, set(), set(), set(), set(), set(), set(), set(), set(), {}, set(), {}
    elif kind in {"UnaryOp", "BinaryOp", "Cast", "ExprList", "ArrayRef", "StructRef"}:
        reads = _ids(ast_node)
    else:
        reads = _ids(ast_node)

    dealloc_set = dealloc_funcs if dealloc_funcs is not None else {"free", "cfree", "vfree"}
    if kind == "FuncCall" and _format_pycparser_expr(ast_node.name) in dealloc_set:
        reads = set()

    asserted: Set[str] = set()
    if kind == "FuncCall" and _format_pycparser_expr(ast_node.name) in {"assert", "ASSERT", "assert_param"}:
        asserted = _ids(ast_node.args) if ast_node.args is not None else set()
    return kind, reads, writes, null_writes, maybe_null_writes, freed, allocated, derefs, asserted, alias_writes, realloc_inputs, realloc_bindings


def build_cfg(funcdef, alloc_funcs: Optional[Set[str]] = None, dealloc_funcs: Optional[Set[str]] = None, realloc_funcs: Optional[Set[str]] = None, summaries: Optional[Dict[str, FunctionSummary]] = None) -> StructuredCFG:
    """Build a structured CFG rooted at a pycparser FuncDef body."""
    from pycparser import c_ast

    cfg = StructuredCFG()
    labels_map: Dict[str, int] = {}
    pending_gotos: List[Tuple[int, str]] = []

    def make_event(stmt) -> int:
        kind, reads, writes, null_writes, maybe_null_writes, freed, allocated, derefs, asserted, alias_writes, realloc_inputs, realloc_bindings = _event_payload(stmt, alloc_funcs=alloc_funcs, dealloc_funcs=dealloc_funcs, realloc_funcs=realloc_funcs, summaries=summaries)
        node_kind = "allocation" if allocated else "free" if freed else kind.lower()
        if kind == "Return":
            expr_str = _format_pycparser_expr(stmt.expr) if getattr(stmt, "expr", None) is not None else ""
        else:
            expr_str = _format_pycparser_expr(stmt)
        return cfg.new_node(node_kind, stmt, expr_str=expr_str, reads=reads, writes=writes, null_writes=null_writes, maybe_null_writes=maybe_null_writes,
                            freed=freed, allocated=allocated, derefs=derefs, asserted=asserted, alias_writes=alias_writes, realloc_inputs=realloc_inputs, realloc_bindings=realloc_bindings)

    def build_compound(items, next_entry, break_target, continue_target):
        current = next_entry
        for item in reversed(items or []):
            current = build_stmt(item, current, break_target, continue_target)
        return current

    def build_case(case_node, next_entry, break_target, continue_target):
        return build_compound(case_node.stmts, next_entry, break_target, continue_target)

    def build_stmt(stmt, next_entry, break_target, continue_target):
        if stmt is None:
            return next_entry
        kind = type(stmt).__name__

        # Handle expression-level control flow: TernaryOp (?:)
        if kind == "If":
            ternary = _find_ternary_op(stmt.cond)
            if ternary is not None:
                coord = getattr(stmt, 'coord', None)
                cond_t = _replace_ast_node(stmt.cond, ternary, ternary.iftrue)
                cond_f = _replace_ast_node(stmt.cond, ternary, ternary.iffalse)
                if_t = c_ast.If(cond=cond_t, iftrue=stmt.iftrue, iffalse=stmt.iffalse, coord=coord)
                if_f = c_ast.If(cond=cond_f, iftrue=stmt.iftrue, iffalse=stmt.iffalse, coord=coord)
                outer_if = c_ast.If(cond=ternary.cond, iftrue=if_t, iffalse=if_f, coord=coord)
                return build_stmt(outer_if, next_entry, break_target, continue_target)
        elif kind not in {"Compound", "While", "DoWhile", "For", "Switch", "Label", "Goto", "Break", "Continue"}:
            ternary = _find_ternary_op(stmt)
            if ternary is not None:
                coord = getattr(stmt, 'coord', None)
                stmt_t = _replace_ast_node(stmt, ternary, ternary.iftrue)
                stmt_f = _replace_ast_node(stmt, ternary, ternary.iffalse)
                if_stmt = c_ast.If(cond=ternary.cond, iftrue=stmt_t, iffalse=stmt_f, coord=coord)
                return build_stmt(if_stmt, next_entry, break_target, continue_target)

        if kind == "Compound":
            return build_compound(stmt.block_items, next_entry, break_target, continue_target)

        if kind in {"Decl", "Assignment", "FuncCall", "Return", "UnaryOp", "BinaryOp", "ExprList", "Cast", "ArrayRef", "StructRef"}:
            node = make_event(stmt)
            is_exit_call = False
            if kind == "FuncCall":
                callee_name = _format_pycparser_expr(getattr(stmt, "name", None))
                if callee_name in {"exit", "_exit", "_Exit", "abort", "quick_exit", "fatal", "panic", "err", "errx"}:
                    is_exit_call = True
            if kind != "Return" and not is_exit_call:
                cfg.connect(node, next_entry)
            return node

        if kind == "ExprList":
            node = make_event(stmt)
            cfg.connect(node, next_entry)
            return node

        if kind == "If":
            cond = cfg.new_node("if_cond", stmt, expr_str=_format_pycparser_expr(stmt.cond), reads=_ids(stmt.cond))
            true_add, true_remove = _simple_null_facts(stmt.cond)
            false_add, false_remove = true_remove, true_add
            # _simple_null_facts returns the nonnull fact for each branch; the
            # opposite fact is represented by removing it from known-nonnull.
            cfg.connect(cond, build_stmt(stmt.iftrue, next_entry, break_target, continue_target),
                        add=true_add, remove={*true_remove})
            if stmt.iffalse is not None:
                cfg.connect(cond, build_stmt(stmt.iffalse, next_entry, break_target, continue_target),
                            add=false_add, remove={*false_remove})
            else:
                cfg.connect(cond, next_entry, add=false_add, remove={*false_remove})
            return cond

        if kind in {"While", "DoWhile"}:
            if kind == "While":
                cond = cfg.new_node("while_cond", stmt, expr_str=_format_pycparser_expr(stmt.cond), reads=_ids(stmt.cond))
                body = build_stmt(stmt.stmt, cond, next_entry, cond)
                true_add, true_remove = _simple_null_facts(stmt.cond)
                false_add, false_remove = true_remove, true_add
                cfg.connect(cond, body, add=true_add, remove=true_remove)
                cfg.connect(cond, next_entry, add=false_add, remove=false_remove)
                return cond
            cond = cfg.new_node("do_cond", stmt, expr_str=_format_pycparser_expr(stmt.cond), reads=_ids(stmt.cond))
            body = build_stmt(stmt.stmt, cond, next_entry, cond)
            true_add, true_remove = _simple_null_facts(stmt.cond)
            false_add, false_remove = true_remove, true_add
            cfg.connect(cond, body, add=true_add, remove=true_remove)
            cfg.connect(cond, next_entry, add=false_add, remove=false_remove)
            return body

        if kind == "For":
            cond_expr = stmt.cond
            cond = cfg.new_node("for_cond", stmt, expr_str=_format_pycparser_expr(cond_expr) if cond_expr else "1",
                                reads=_ids(cond_expr) if cond_expr is not None else set())
            iter_node = None
            if stmt.next is not None:
                iter_node = make_event(stmt.next)
                cfg.connect(iter_node, cond)
            body = build_stmt(stmt.stmt, iter_node or cond, next_entry, iter_node or cond)
            true_add, true_remove = _simple_null_facts(cond_expr)
            false_add, false_remove = true_remove, true_add
            cfg.connect(cond, body, add=true_add, remove=true_remove)
            cfg.connect(cond, next_entry, add=false_add, remove=false_remove)
            if stmt.init is not None:
                init_node = make_event(stmt.init)
                cfg.connect(init_node, cond)
                return init_node
            return cond

        if kind == "Switch":
            switch_node = cfg.new_node("switch_cond", stmt, expr_str=_format_pycparser_expr(stmt.cond), reads=_ids(stmt.cond))
            body = stmt.stmt
            cases = list(getattr(body, "block_items", []) or []) if type(body).__name__ == "Compound" else []
            case_entries = [None] * len(cases)
            fallthrough = next_entry
            for i in range(len(cases) - 1, -1, -1):
                case = cases[i]
                if type(case).__name__ not in {"Case", "Default"}:
                    continue
                case_entries[i] = build_case(case, fallthrough, next_entry, continue_target)
                fallthrough = case_entries[i]
            for entry in case_entries:
                if entry is not None:
                    cfg.connect(switch_node, entry)
            if not any(type(c).__name__ == "Default" for c in cases):
                cfg.connect(switch_node, next_entry)
            return switch_node

        if kind == "Break":
            node = make_event(stmt)
            cfg.connect(node, break_target)
            return node

        if kind == "Continue":
            node = make_event(stmt)
            cfg.connect(node, continue_target)
            return node

        if kind == "Label":
            label_node = cfg.new_node("label", stmt, expr_str=stmt.name)
            labels_map[stmt.name] = label_node
            inner_entry = build_stmt(stmt.stmt, next_entry, break_target, continue_target)
            cfg.connect(label_node, inner_entry)
            return label_node

        if kind == "Goto":
            goto_node = cfg.new_node("goto", stmt, expr_str=f"goto {stmt.name}")
            pending_gotos.append((goto_node, stmt.name))
            return goto_node

        # Other less-common constructs retain the conservative source-order behavior.
        node = make_event(stmt)
        cfg.connect(node, next_entry)
        return node

    cfg.entry = build_stmt(funcdef.body, None, None, None)

    for goto_node, label_name in pending_gotos:
        if label_name in labels_map:
            cfg.connect(goto_node, labels_map[label_name])

    cfg.build_basic_blocks()
    return cfg


def find_function_def(ast, name: str):
    for ext in getattr(ast, "ext", []) or []:
        if type(ext).__name__ == "FuncDef" and getattr(ext.decl, "name", None) == name:
            return ext
    return None


def _get_builtin_summaries(alloc_funcs: Optional[Set[str]] = None, dealloc_funcs: Optional[Set[str]] = None, realloc_funcs: Optional[Set[str]] = None) -> Dict[str, FunctionSummary]:
    alloc_set = alloc_funcs if alloc_funcs is not None else {"malloc", "calloc", "realloc", "aligned_alloc", "strdup", "strndup", "valloc", "pvalloc", "memalign"}
    dealloc_set = dealloc_funcs if dealloc_funcs is not None else {"free", "cfree", "vfree"}
    if realloc_funcs:
        alloc_set.update(realloc_funcs)

    builtins: Dict[str, FunctionSummary] = {}
    for f in dealloc_set:
        builtins[f] = FunctionSummary(freed_params={0}, return_nullness=Nullness.UNKNOWN, returns_allocation=False)
    for f in alloc_set:
        builtins[f] = FunctionSummary(freed_params=set(), return_nullness=Nullness.MAYBE_NULL, returns_allocation=True)
    return builtins


def analyze_function_summaries(ast_ctx, alloc_funcs: Optional[Set[str]] = None, dealloc_funcs: Optional[Set[str]] = None, realloc_funcs: Optional[Set[str]] = None) -> Dict[str, FunctionSummary]:
    """
    Computes intra-file interprocedural function summaries for all functions defined in ast_ctx.
    Performs fixed-point iteration to propagate parameter deallocations and return values across callers/callees.
    """
    summaries: Dict[str, FunctionSummary] = _get_builtin_summaries(alloc_funcs=alloc_funcs, dealloc_funcs=dealloc_funcs, realloc_funcs=realloc_funcs)

    if not hasattr(ast_ctx, "functions") or not ast_ctx.functions:
        return summaries

    # Map function name to CFunction
    fn_map = {fn.name: fn for fn in ast_ctx.functions if getattr(fn, "name", None)}

    # Initialize summaries for all user-defined functions
    for name in fn_map:
        if name not in summaries:
            summaries[name] = FunctionSummary()

    # Fixed-point iteration
    changed = True
    max_iters = len(fn_map) * 3 + 10
    iters = 0

    while changed and iters < max_iters:
        changed = False
        iters += 1

        for name, fn in fn_map.items():
            old_summary = summaries[name]
            param_names = [p.name for p in fn.parameters if p.name]

            # Build CFG using current summaries
            cfg = None
            if getattr(ast_ctx, "has_pycparser", False) and ast_ctx.pycparser_ast is not None:
                funcdef = find_function_def(ast_ctx.pycparser_ast, name)
                if funcdef is not None:
                    cfg = build_cfg(funcdef, alloc_funcs=alloc_funcs, dealloc_funcs=dealloc_funcs, realloc_funcs=realloc_funcs, summaries=summaries)

            freed_params: Set[int] = set()
            return_nullness_set: Set[Nullness] = set()
            returns_alloc: bool = False

            if cfg is not None:
                initial_initialized = set(p.name for p in fn.parameters if p.name) | set(getattr(ast_ctx, "global_variables", {}).keys()) | {v for v, var in fn.variables.items() if var.has_initializer}
                cfg.analyze_dataflow(initial_nonnull=set(), initial_initialized=initial_initialized)

                # Check parameter deallocation
                for i, p_name in enumerate(param_names):
                    for node in cfg.nodes.values():
                        if p_name in node.freed:
                            freed_params.add(i)
                            break

                # Inspect return statements
                for node in cfg.nodes.values():
                    if node.kind == "return":
                        ret_expr = node.expr_str.strip()
                        ret_ast = getattr(node, "_ast_node", None)
                        expr_ast = getattr(ret_ast, "expr", None) if ret_ast is not None else None

                        ret_nullness = Nullness.UNKNOWN
                        if ret_expr in param_names:
                            ret_nullness = cfg.query_nullness(ret_expr, node.node_id)
                        elif ret_expr in fn.variables:
                            ret_nullness = cfg.query_nullness(ret_expr, node.node_id)
                            if cfg.query_allocation(ret_expr, node.node_id) in (Allocation.ALLOCATED, Allocation.MAYBE_ALLOCATED):
                                returns_alloc = True
                                if ret_nullness == Nullness.UNKNOWN:
                                    ret_nullness = Nullness.MAYBE_NULL
                        elif expr_ast is not None and type(expr_ast).__name__ == "FuncCall":
                            callee = _format_pycparser_expr(expr_ast.name)
                            callee_summary = summaries.get(callee)
                            if callee_summary:
                                ret_nullness = callee_summary.return_nullness
                                if callee_summary.returns_allocation:
                                    returns_alloc = True
                        elif expr_ast is not None and _is_nullish(expr_ast):
                            ret_nullness = Nullness.NULL
                        elif ret_expr in {"NULL", "nullptr", "0", "0x0", "(void*)0", "(void *)0"}:
                            ret_nullness = Nullness.NULL

                        return_nullness_set.add(ret_nullness)

            # Combine return nullness facts across return branches
            if not return_nullness_set:
                final_ret_nullness = Nullness.UNKNOWN
            else:
                final_ret_nullness = None
                for rn in return_nullness_set:
                    if final_ret_nullness is None:
                        final_ret_nullness = rn
                    else:
                        final_ret_nullness = meet_nullness(final_ret_nullness, rn)

            new_summary = FunctionSummary(
                freed_params=freed_params,
                return_nullness=final_ret_nullness if final_ret_nullness is not None else Nullness.UNKNOWN,
                returns_allocation=returns_alloc,
                is_unknown=False,
            )

            if new_summary != old_summary:
                summaries[name] = new_summary
                changed = True

    return summaries
