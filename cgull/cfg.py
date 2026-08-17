"""Small, path-sensitive control-flow graph builder for C-GULL AST rules.

This module intentionally models only the structured C control-flow constructs
needed by the memory-safety rules.  It is used only when pycparser produced a
real AST; the existing lexical fallback remains available otherwise.
"""
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .ast_analyzer import _extract_identifiers_from_ast, _format_pycparser_expr, _PRELUDE_LINE_COUNT


@dataclass
class CFGEvent:
    node_id: int
    kind: str
    line_number: int
    expr_str: str = ""
    reads: Set[str] = field(default_factory=set)
    writes: Set[str] = field(default_factory=set)
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


def _freed_vars(node) -> Set[str]:
    freed: Set[str] = set()
    for callee in ("free", "cfree", "vfree"):
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


def _deref_vars(node) -> Set[str]:
    result: Set[str] = set()
    if node is None:
        return result
    kind = type(node).__name__
    if kind == "UnaryOp" and getattr(node, "op", None) == "*":
        if type(node.expr).__name__ == "ID":
            result.add(str(node.expr.name))
    elif kind == "ArrayRef":
        if type(node.name).__name__ == "ID":
            result.add(str(node.name.name))
    elif kind == "StructRef" and type(node.name).__name__ == "ID":
        result.add(str(node.name.name))
    for _, child in node.children():
        result.update(_deref_vars(child))
    return result


def _assignment_target(node) -> Set[str]:
    if node is None:
        return set()
    if type(node).__name__ == "ID":
        return {str(node.name)}
    return set()


def _is_nullish(node) -> bool:
    if node is None:
        return False
    kind = type(node).__name__
    if kind == "ID":
        return str(node.name) in {"NULL", "nullptr"}
    if kind == "Cast":
        return _is_nullish(node.expr)
    return kind == "Constant" and str(getattr(node, "value", "")) in {"0", "0L", "0UL", "0LL", "0ULL"}


def _simple_null_facts(cond) -> Tuple[Set[str], Set[str]]:
    """Return (true-edge nonnull facts, false-edge nonnull facts)."""
    if cond is None:
        return set(), set()
    kind = type(cond).__name__
    if kind == "ID":
        return {str(cond.name)}, set()
    if kind == "UnaryOp" and getattr(cond, "op", None) == "!" and type(cond.expr).__name__ == "ID":
        return set(), {str(cond.expr.name)}
    if kind == "BinaryOp":
        op = getattr(cond, "op", None)
        if op in {"==", "!="}:
            lhs, rhs = cond.left, cond.right
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
            l_t, l_f = _simple_null_facts(cond.left)
            r_t, r_f = _simple_null_facts(cond.right)
            return l_t.intersection(r_t), l_f.union(r_f)
        elif op == "&&":
            l_t, l_f = _simple_null_facts(cond.left)
            r_t, r_f = _simple_null_facts(cond.right)
            return l_t.union(r_t), l_f.intersection(r_f)
    return set(), set()


def _event_payload(ast_node) -> Tuple[str, Set[str], Set[str], Set[str], Set[str], Set[str], Set[str]]:
    """kind, reads, writes, freed, allocated, derefs, asserted for an executable AST node."""
    kind = type(ast_node).__name__
    reads: Set[str] = set()
    writes: Set[str] = set()
    freed: Set[str] = _freed_vars(ast_node)
    allocated: Set[str] = set()
    derefs = _deref_vars(ast_node)
    expr = _format_pycparser_expr(ast_node)

    if kind == "Decl":
        if ast_node.init is not None:
            reads = _ids(ast_node.init)
            writes = {str(ast_node.name)} if ast_node.name else set()
            for alloc_name in ("malloc", "calloc", "realloc", "aligned_alloc"):
                if alloc_name in _call_names(ast_node.init):
                    if ast_node.name:
                        allocated.add(str(ast_node.name))
                    break
    elif kind == "Assignment":
        reads = _ids(ast_node.rvalue)
        writes = _assignment_target(ast_node.lvalue)
        for alloc_name in ("malloc", "calloc", "realloc", "aligned_alloc"):
            if alloc_name in _call_names(ast_node.rvalue):
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

    if kind == "FuncCall" and _format_pycparser_expr(ast_node.name) in {"free", "cfree", "vfree"}:
        reads = set()

    asserted: Set[str] = set()
    if kind == "FuncCall" and _format_pycparser_expr(ast_node.name) in {"assert", "ASSERT", "assert_param"}:
        asserted = _ids(ast_node.args) if ast_node.args is not None else set()
    return kind, reads, writes, freed, allocated, derefs, asserted


def build_cfg(funcdef) -> StructuredCFG:
    """Build a structured CFG rooted at a pycparser FuncDef body."""
    from pycparser import c_ast

    cfg = StructuredCFG()

    def make_event(stmt) -> int:
        kind, reads, writes, freed, allocated, derefs, asserted = _event_payload(stmt)
        node_kind = "allocation" if allocated else "free" if freed else kind.lower()
        return cfg.new_node(node_kind, stmt, expr_str=_format_pycparser_expr(stmt), reads=reads, writes=writes,
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
    return cfg


def find_function_def(ast, name: str):
    for ext in getattr(ast, "ext", []) or []:
        if type(ext).__name__ == "FuncDef" and getattr(ext.decl, "name", None) == name:
            return ext
    return None
