"""CFG graph representation and forward data-flow analysis."""

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .model import Allocation, BasicBlock, CFGEvent, CFGSourceLocation, Initialization, Nullness, VariableFacts
from . import model
from ..ast_analyzer import _PRELUDE_LINE_COUNT, _map_line


def _find_value_producing_call(node):
    # Import lazily: construction itself depends on StructuredCFG.
    from .construction import _find_value_producing_call as implementation
    return implementation(node)

def _is_nullish(node):
    from .construction import _is_nullish as implementation
    return implementation(node)

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

    def new_node(self, kind: str, ast_node=None, line_map: Optional[Dict[int, Any]] = None, **kwargs) -> int:
        self._next_id += 1
        line = 1
        source_path = None
        column = 0
        if ast_node is not None and getattr(ast_node, "coord", None):
            exp_line = max(1, ast_node.coord.line - _PRELUDE_LINE_COUNT)
            line = _map_line(exp_line, line_map)
            mapped = line_map.get(exp_line) if line_map else None
            source_path = getattr(mapped, "file_path", None) if mapped is not None else getattr(ast_node.coord, "file", None)
            column = getattr(ast_node.coord, "column", 0) or 0
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

                        valid_blocks = {block.block_id}
                        v_queue = [block.block_id]
                        while v_queue:
                            curr_v = v_queue.pop(0)
                            for succ_b_id in self.blocks[curr_v].successors:
                                succ_b = self.blocks.get(succ_b_id)
                                if succ_b and len(succ_b.predecessors) == 1 and succ_b_id not in valid_blocks:
                                    valid_blocks.add(succ_b_id)
                                    v_queue.append(succ_b_id)

                        self.realloc_records[new_loc_id] = (target_var, input_ptr, input_locs, pre_states, size_is_zero, valid_blocks)

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
                for new_loc_id, rec in self.realloc_records.items():
                    if len(rec) == 6:
                        target_var, input_ptr, input_locs, pre_states, size_is_zero, valid_blocks = rec
                    else:
                        target_var, input_ptr, input_locs, pre_states, size_is_zero = rec
                        valid_blocks = None

                    if valid_blocks is not None and block.block_id not in valid_blocks:
                        continue

                    if new_loc_id in curr_loc_map.get(target_var, set()):
                        if curr_null.get(target_var, Nullness.UNKNOWN) in (Nullness.MAYBE_NULL, Nullness.UNKNOWN):
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
                        valid_blocks = {block.block_id}
                        v_queue = [block.block_id]
                        while v_queue:
                            curr_v = v_queue.pop(0)
                            for succ_b_id in self.blocks[curr_v].successors:
                                succ_b = self.blocks.get(succ_b_id)
                                if succ_b and len(succ_b.predecessors) == 1 and succ_b_id not in valid_blocks:
                                    valid_blocks.add(succ_b_id)
                                    v_queue.append(succ_b_id)
                        if hasattr(self, "realloc_records"):
                            self.realloc_records[new_loc_id] = (target_var, input_ptr, input_locs, pre_states, size_is_zero, valid_blocks)

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


