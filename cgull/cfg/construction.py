"""Structured CFG construction and AST event extraction."""

from typing import Any, Dict, List, Optional, Set, Tuple

from ..ast_analyzer import _PRELUDE_LINE_COUNT, _extract_identifiers_from_ast, _format_pycparser_expr, _map_line
from .model import Allocation, CFGEvent, FunctionSummary, Initialization, Nullness
from .dataflow import StructuredCFG

from .dataflow import meet_allocation, meet_initialization, meet_nullness

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


def _all_calls_args(node, callee: str) -> List[list]:
    results = []
    if node is None:
        return results
    if type(node).__name__ == "FuncCall" and _format_pycparser_expr(node.name) == callee:
        results.append(list(getattr(node.args, "exprs", []) or []))
    for _, child in node.children():
        results.extend(_all_calls_args(child, callee))
    return results


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


def _deref_vars_with_lines(node, default_line: Optional[int] = None, line_map: Optional[Dict[int, Any]] = None) -> Dict[str, int]:
    result: Dict[str, int] = {}
    if node is None:
        return result
    kind = type(node).__name__
    matched_var = None
    if kind == "UnaryOp" and getattr(node, "op", None) == "*":
        inner = _unwrap_cast(node.expr)
        if inner is not None and type(inner).__name__ == "ID":
            matched_var = str(inner.name)
    elif kind == "ArrayRef":
        inner = _unwrap_cast(node.name)
        if inner is not None and type(inner).__name__ == "ID":
            matched_var = str(inner.name)
    elif kind == "StructRef":
        inner = _unwrap_cast(node.name)
        if inner is not None and type(inner).__name__ == "ID":
            matched_var = str(inner.name)

    if matched_var:
        coord = getattr(node, "coord", None)
        if coord is not None:
            exp_line = max(1, coord.line - _PRELUDE_LINE_COUNT)
            line = _map_line(exp_line, line_map)
        elif default_line is not None:
            line = default_line
        else:
            line = 1
        result[matched_var] = line

    for _, child in node.children():
        child_res = _deref_vars_with_lines(child, default_line=default_line, line_map=line_map)
        for var, line in child_res.items():
            if var not in result:
                result[var] = line

    return result


def _deref_vars(node, default_line: Optional[int] = None) -> Set[str]:
    return set(_deref_vars_with_lines(node, default_line=default_line).keys())


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


def _direct_deref_var(node) -> Optional[str]:
    """Return the pointer directly dereferenced by one AST node, if any."""
    if node is None:
        return None
    kind = type(node).__name__
    if kind == "UnaryOp" and getattr(node, "op", None) == "*":
        inner = _unwrap_cast(node.expr)
    elif kind in {"ArrayRef", "StructRef"}:
        inner = _unwrap_cast(node.name)
    else:
        return None
    return str(inner.name) if inner is not None and type(inner).__name__ == "ID" else None


def _guarded_expression_uses(node, known_nonnull: Optional[Set[str]] = None):
    """Yield ``(kind, payload, known_nonnull)`` for expression uses.

    The CFG models a full expression as one event.  Preserve simple
    short-circuit and ternary proofs for a use in a later operand so clients
    do not have to treat the event's pre-state as the use's state.
    """
    if node is None:
        return
    known = set(known_nonnull or ())
    kind = type(node).__name__

    # CFG condition nodes hold the entire statement as their AST node.  The
    # body has independent CFG events, so only inspect the condition here.
    if kind in {"If", "While", "DoWhile", "Switch"}:
        yield from _guarded_expression_uses(getattr(node, "cond", None), known)
        return
    if kind == "For":
        yield from _guarded_expression_uses(getattr(node, "cond", None), known)
        return

    if kind == "FuncCall":
        yield "call", node, known
        for arg in list(getattr(node.args, "exprs", []) or []) if node.args else []:
            yield from _guarded_expression_uses(arg, known)
        return

    if kind == "BinaryOp" and getattr(node, "op", None) in {"&&", "||"}:
        yield from _guarded_expression_uses(node.left, known)
        true_nonnull, false_nonnull = _simple_null_facts(node.left)
        right_known = known | (true_nonnull if node.op == "&&" else false_nonnull)
        yield from _guarded_expression_uses(node.right, right_known)
        return

    if kind == "TernaryOp":
        yield from _guarded_expression_uses(node.cond, known)
        true_nonnull, false_nonnull = _simple_null_facts(node.cond)
        yield from _guarded_expression_uses(node.iftrue, known | true_nonnull)
        yield from _guarded_expression_uses(node.iffalse, known | false_nonnull)
        return

    deref_var = _direct_deref_var(node)
    if deref_var:
        yield "deref", deref_var, known
    for _, child in node.children():
        yield from _guarded_expression_uses(child, known)


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


def _event_payload(ast_node, alloc_funcs: Optional[Set[str]] = None, dealloc_funcs: Optional[Set[str]] = None, realloc_funcs: Optional[Set[str]] = None, summaries: Optional[Dict[str, FunctionSummary]] = None, line_map: Optional[Dict[int, Any]] = None) -> Tuple[str, Set[str], Set[str], Set[str], Set[str], Set[str], Set[str], Set[str], Dict[str, int], Set[str], Dict[str, str], Set[str], Dict[str, str]]:
    """kind, reads, writes, null_writes, maybe_null_writes, freed, allocated, derefs, deref_lines, asserted, alias_writes, realloc_inputs, realloc_bindings for an executable AST node."""
    kind = type(ast_node).__name__
    reads: Set[str] = set()
    writes: Set[str] = set()
    null_writes: Set[str] = set()
    maybe_null_writes: Set[str] = set()
    freed: Set[str] = _freed_vars(ast_node, dealloc_funcs=dealloc_funcs)
    allocated: Set[str] = set()
    stmt_coord = getattr(ast_node, "coord", None)
    if stmt_coord is not None:
        exp_line = max(1, stmt_coord.line - _PRELUDE_LINE_COUNT)
        default_line = _map_line(exp_line, line_map)
    else:
        default_line = 1
    deref_lines = _deref_vars_with_lines(ast_node, default_line=default_line, line_map=line_map)
    derefs = set(deref_lines.keys())
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
                        for args in _all_calls_args(ast_node.init, call_name):
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
                    for args in _all_calls_args(ast_node.rvalue, call_name):
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
        return kind, set(), set(), set(), set(), set(), set(), set(), {}, set(), {}, set(), {}
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
    return kind, reads, writes, null_writes, maybe_null_writes, freed, allocated, derefs, deref_lines, asserted, alias_writes, realloc_inputs, realloc_bindings


def build_cfg(funcdef, alloc_funcs: Optional[Set[str]] = None, dealloc_funcs: Optional[Set[str]] = None, realloc_funcs: Optional[Set[str]] = None, summaries: Optional[Dict[str, FunctionSummary]] = None, line_map: Optional[Dict[int, Any]] = None) -> StructuredCFG:
    """Build a structured CFG rooted at a pycparser FuncDef body."""
    from pycparser import c_ast

    cfg = StructuredCFG()
    labels_map: Dict[str, int] = {}
    pending_gotos: List[Tuple[int, str]] = []

    def make_event(stmt) -> int:
        kind, reads, writes, null_writes, maybe_null_writes, freed, allocated, derefs, deref_lines, asserted, alias_writes, realloc_inputs, realloc_bindings = _event_payload(stmt, alloc_funcs=alloc_funcs, dealloc_funcs=dealloc_funcs, realloc_funcs=realloc_funcs, summaries=summaries, line_map=line_map)
        node_kind = "allocation" if allocated else "free" if freed else kind.lower()
        if kind == "Return":
            expr_str = _format_pycparser_expr(stmt.expr) if getattr(stmt, "expr", None) is not None else ""
        else:
            expr_str = _format_pycparser_expr(stmt)
        return cfg.new_node(node_kind, stmt, line_map=line_map, expr_str=expr_str, reads=reads, writes=writes, null_writes=null_writes, maybe_null_writes=maybe_null_writes,
                            freed=freed, allocated=allocated, derefs=derefs, deref_lines=deref_lines, asserted=asserted, alias_writes=alias_writes, realloc_inputs=realloc_inputs, realloc_bindings=realloc_bindings)

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
            cond = cfg.new_node("if_cond", stmt, line_map=line_map, expr_str=_format_pycparser_expr(stmt.cond), reads=_ids(stmt.cond))
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
                cond = cfg.new_node("while_cond", stmt, line_map=line_map, expr_str=_format_pycparser_expr(stmt.cond), reads=_ids(stmt.cond))
                body = build_stmt(stmt.stmt, cond, next_entry, cond)
                true_add, true_remove = _simple_null_facts(stmt.cond)
                false_add, false_remove = true_remove, true_add
                cfg.connect(cond, body, add=true_add, remove=true_remove)
                cfg.connect(cond, next_entry, add=false_add, remove=false_remove)
                return cond
            cond = cfg.new_node("do_cond", stmt, line_map=line_map, expr_str=_format_pycparser_expr(stmt.cond), reads=_ids(stmt.cond))
            body = build_stmt(stmt.stmt, cond, next_entry, cond)
            true_add, true_remove = _simple_null_facts(stmt.cond)
            false_add, false_remove = true_remove, true_add
            cfg.connect(cond, body, add=true_add, remove=true_remove)
            cfg.connect(cond, next_entry, add=false_add, remove=false_remove)
            return body

        if kind == "For":
            cond_expr = stmt.cond
            cond = cfg.new_node("for_cond", stmt, line_map=line_map, expr_str=_format_pycparser_expr(cond_expr) if cond_expr else "1",
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
            switch_node = cfg.new_node("switch_cond", stmt, line_map=line_map, expr_str=_format_pycparser_expr(stmt.cond), reads=_ids(stmt.cond))
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
            label_node = cfg.new_node("label", stmt, line_map=line_map, expr_str=stmt.name)
            labels_map[stmt.name] = label_node
            inner_entry = build_stmt(stmt.stmt, next_entry, break_target, continue_target)
            cfg.connect(label_node, inner_entry)
            return label_node

        if kind == "Goto":
            goto_node = cfg.new_node("goto", stmt, line_map=line_map, expr_str=f"goto {stmt.name}")
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


