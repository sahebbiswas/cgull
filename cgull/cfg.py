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
    FREED = "FREED"
    MAYBE_FREED = "MAYBE_FREED"


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


@dataclass
class CFGEvent:
    node_id: int
    kind: str
    line_number: int
    expr_str: str = ""
    reads: Set[str] = field(default_factory=set)
    writes: Set[str] = field(default_factory=set)
    null_writes: Set[str] = field(default_factory=set)
    freed: Set[str] = field(default_factory=set)
    allocated: Set[str] = field(default_factory=set)
    derefs: Set[str] = field(default_factory=set)
    asserted: Set[str] = field(default_factory=set)
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

        init_nonnull = set(initial_nonnull) if initial_nonnull else set()
        init_initialized = set(initial_initialized) if initial_initialized else set()

        for block in self.blocks.values():
            block.nullness_in = {}
            block.nullness_out = {}
            block.init_in = {}
            block.init_out = {}
            block.alloc_in = {}
            block.alloc_out = {}

        entry_block_id = self.node_to_block.get(self.entry) if self.entry else min(self.blocks.keys())
        entry_block = self.blocks.get(entry_block_id)

        if entry_block:
            for v in all_vars:
                entry_block.nullness_in[v] = Nullness.NON_NULL if v in init_nonnull else Nullness.UNKNOWN
                entry_block.init_in[v] = Initialization.INITIALIZED if v in init_initialized else Initialization.UNINITIALIZED
                entry_block.alloc_in[v] = Allocation.NOT_ALLOCATED

        worklist = list(self.blocks.keys())

        while worklist:
            b_id = worklist.pop(0)
            block = self.blocks[b_id]

            curr_null = dict(block.nullness_in)
            curr_init = dict(block.init_in)
            curr_alloc = dict(block.alloc_in)

            for node in block.nodes:
                for v in node.allocated:
                    curr_alloc[v] = Allocation.ALLOCATED
                    curr_null[v] = Nullness.MAYBE_NULL
                    curr_init[v] = Initialization.INITIALIZED

                for v in node.freed:
                    curr_alloc[v] = Allocation.FREED

                for v in node.writes:
                    curr_init[v] = Initialization.INITIALIZED
                    if v not in node.allocated:
                        curr_alloc[v] = Allocation.NOT_ALLOCATED
                        if v in node.null_writes or "NULL" in node.expr_str or "nullptr" in node.expr_str:
                            curr_null[v] = Nullness.NULL
                        else:
                            curr_null[v] = Nullness.UNKNOWN

                for v in node.asserted:
                    curr_null[v] = Nullness.NON_NULL
                for v in node.derefs:
                    curr_null[v] = Nullness.NON_NULL

            block.nullness_out = curr_null
            block.init_out = curr_init
            block.alloc_out = curr_alloc

            for succ_id in block.successors:
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

                    # Alloc
                    e_alloc = curr_alloc.get(v, Allocation.NOT_ALLOCATED)
                    if v not in succ_block.alloc_in:
                        new_alloc = e_alloc
                    else:
                        new_alloc = meet_allocation(succ_block.alloc_in[v], e_alloc)
                    if succ_block.alloc_in.get(v) != new_alloc:
                        succ_block.alloc_in[v] = new_alloc
                        changed = True

                if changed and succ_id not in worklist:
                    worklist.append(succ_id)

        self._compute_node_level_facts(all_vars)

    def _compute_node_level_facts(self, all_vars: Set[str]) -> None:
        self.node_facts: Dict[int, Dict[str, VariableFacts]] = {}
        for block in self.blocks.values():
            curr_null = dict(block.nullness_in)
            curr_init = dict(block.init_in)
            curr_alloc = dict(block.alloc_in)

            for node in block.nodes:
                self.node_facts[node.node_id] = {
                    v: VariableFacts(
                        nullness=curr_null.get(v, Nullness.UNKNOWN),
                        initialization=curr_init.get(v, Initialization.UNINITIALIZED),
                        allocation=curr_alloc.get(v, Allocation.NOT_ALLOCATED),
                    )
                    for v in all_vars
                }

                for v in node.allocated:
                    curr_alloc[v] = Allocation.ALLOCATED
                    curr_null[v] = Nullness.MAYBE_NULL
                    curr_init[v] = Initialization.INITIALIZED

                for v in node.freed:
                    curr_alloc[v] = Allocation.FREED

                for v in node.writes:
                    curr_init[v] = Initialization.INITIALIZED
                    if v not in node.allocated:
                        curr_alloc[v] = Allocation.NOT_ALLOCATED
                        if v in node.null_writes or "NULL" in node.expr_str or "nullptr" in node.expr_str:
                            curr_null[v] = Nullness.NULL
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
    if (a == Allocation.ALLOCATED and b == Allocation.NOT_ALLOCATED) or \
       (a == Allocation.NOT_ALLOCATED and b == Allocation.ALLOCATED):
        return Allocation.NOT_ALLOCATED
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
            if type(arg).__name__ == "ID":
                freed.add(str(arg.name))
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


def _event_payload(ast_node, alloc_funcs: Optional[Set[str]] = None, dealloc_funcs: Optional[Set[str]] = None) -> Tuple[str, Set[str], Set[str], Set[str], Set[str], Set[str], Set[str], Set[str]]:
    """kind, reads, writes, null_writes, freed, allocated, derefs, asserted for an executable AST node."""
    kind = type(ast_node).__name__
    reads: Set[str] = set()
    writes: Set[str] = set()
    null_writes: Set[str] = set()
    freed: Set[str] = _freed_vars(ast_node, dealloc_funcs=dealloc_funcs)
    allocated: Set[str] = set()
    derefs = _deref_vars(ast_node)
    expr = _format_pycparser_expr(ast_node)

    alloc_set = alloc_funcs if alloc_funcs is not None else {"malloc", "calloc", "realloc", "aligned_alloc"}

    if kind == "Decl":
        if ast_node.init is not None:
            reads = _ids(ast_node.init)
            writes = {str(ast_node.name)} if ast_node.name else set()
            if _is_nullish(ast_node.init):
                null_writes.update(writes)
            for call_name in _call_names(ast_node.init):
                if call_name in alloc_set:
                    if ast_node.name:
                        allocated.add(str(ast_node.name))
                    break
    elif kind == "Assignment":
        reads = _ids(ast_node.rvalue)
        writes = _assignment_target(ast_node.lvalue)
        if _is_nullish(ast_node.rvalue):
            null_writes.update(writes)
        for call_name in _call_names(ast_node.rvalue):
            if call_name in alloc_set:
                allocated.update(writes)
                break
    elif kind == "FuncCall":
        reads = _ids(ast_node.args) if ast_node.args is not None else set()
    elif kind == "Return":
        reads = _ids(ast_node.expr) if ast_node.expr is not None else set()
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
    return kind, reads, writes, null_writes, freed, allocated, derefs, asserted


def build_cfg(funcdef, alloc_funcs: Optional[Set[str]] = None, dealloc_funcs: Optional[Set[str]] = None) -> StructuredCFG:
    """Build a structured CFG rooted at a pycparser FuncDef body."""
    from pycparser import c_ast

    cfg = StructuredCFG()

    def make_event(stmt) -> int:
        kind, reads, writes, null_writes, freed, allocated, derefs, asserted = _event_payload(stmt, alloc_funcs=alloc_funcs, dealloc_funcs=dealloc_funcs)
        node_kind = "allocation" if allocated else "free" if freed else kind.lower()
        return cfg.new_node(node_kind, stmt, expr_str=_format_pycparser_expr(stmt), reads=reads, writes=writes, null_writes=null_writes,
                            freed=freed, allocated=allocated, derefs=derefs, asserted=asserted)

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

        # Label/goto and other less-common constructs retain the conservative
        # source-order behavior within the surrounding structured block.
        node = make_event(stmt)
        cfg.connect(node, next_entry)
        return node

    cfg.entry = build_stmt(funcdef.body, None, None, None)
    cfg.build_basic_blocks()
    return cfg


def find_function_def(ast, name: str):
    for ext in getattr(ast, "ext", []) or []:
        if type(ext).__name__ == "FuncDef" and getattr(ext.decl, "name", None) == name:
            return ext
    return None
