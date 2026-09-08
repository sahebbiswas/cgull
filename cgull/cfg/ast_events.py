"""AST-facing helpers for CFG event extraction.

This module owns pycparser-specific expression inspection and translation into
CFG event payloads.  It deliberately does not depend on graph construction or
data-flow so both layers can consume the same AST semantics without circular
imports.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from ..ast_analyzer import (
    _PRELUDE_LINE_COUNT,
    _extract_identifiers_from_ast,
    _format_pycparser_expr,
    _map_line,
)
from .model import CFGCall, CFGSourceLocation, FunctionSummary, Nullness


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


def _deref_vars_with_lines(
    node,
    default_line: Optional[int] = None,
    line_map: Optional[Dict[int, Any]] = None,
) -> Dict[str, int]:
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
        child_res = _deref_vars_with_lines(
            child, default_line=default_line, line_map=line_map
        )
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
    return kind == "Constant" and str(getattr(inner, "value", "")) in {
        "0",
        "0x0",
        "0L",
        "0UL",
        "0LL",
        "0ULL",
    }


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
    """Yield ``(kind, payload, known_nonnull)`` for expression uses."""
    if node is None:
        return
    known = set(known_nonnull or ())
    kind = type(node).__name__

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


def _process_call_effects(
    call_node,
    target_var: Optional[str],
    summaries: Optional[Dict[str, FunctionSummary]],
    alloc_set: Set[str],
    realloc_set: Set[str],
    freed: Set[str],
    allocated: Set[str],
    null_writes: Set[str],
    maybe_null_writes: Set[str],
    realloc_inputs: Set[str],
    realloc_bindings: Dict[str, str],
    is_value_producing: bool = False,
):
    callee = _format_pycparser_expr(call_node.name)
    args = list(getattr(call_node.args, "exprs", []) or []) if call_node.args else []
    summary = summaries.get(callee) if summaries else None

    if summary and summary.freed_params:
        for p_idx in summary.freed_params:
            if p_idx < len(args):
                arg_unwrapped = _unwrap_cast(args[p_idx])
                if arg_unwrapped is not None and type(arg_unwrapped).__name__ == "ID":
                    freed.add(str(arg_unwrapped.name))

    if target_var:
        if callee in alloc_set or (summary and summary.returns_allocation):
            allocated.add(target_var)
            if callee in realloc_set and args:
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


def _find_ternary_op(node):
    if node is None:
        return None
    if type(node).__name__ == "TernaryOp":
        return node
    for _, child in node.children():
        res = _find_ternary_op(child)
        if res is not None:
            return res
    return None


def _replace_ast_node(tree, target, replacement):
    from pycparser import c_ast
    import copy

    if tree is target:
        return replacement
    if tree is None:
        return None
    tree_copy = copy.copy(tree)
    slots = set()
    for cls in type(tree_copy).__mro__:
        slots.update(getattr(cls, "__slots__", ()))
    for attr in slots:
        val = getattr(tree_copy, attr, None)
        if isinstance(val, list):
            setattr(
                tree_copy,
                attr,
                [
                    _replace_ast_node(item, target, replacement)
                    if isinstance(item, c_ast.Node)
                    else item
                    for item in val
                ],
            )
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


def _is_function_pointer_type(type_node) -> bool:
    node = type_node
    while node is not None:
        if type(node).__name__ == "PtrDecl" and type(getattr(node, "type", None)).__name__ == "FuncDecl":
            return True
        node = getattr(node, "type", None)
    return False


def _function_pointer_names(funcdef) -> Set[str]:
    names: Set[str] = set()
    if funcdef is None:
        return names

    from pycparser import c_ast

    class Visitor(c_ast.NodeVisitor):
        def visit_Decl(self, node):
            if getattr(node, "name", None) and _is_function_pointer_type(getattr(node, "type", None)):
                names.add(str(node.name))
            self.generic_visit(node)

    Visitor().visit(funcdef)
    return names


def _call_source_location(call_node, line_map: Optional[Dict[int, Any]]) -> CFGSourceLocation:
    coord = getattr(call_node, "coord", None)
    if coord is None:
        return CFGSourceLocation(file_path=None, line_number=1)

    exp_line = max(1, coord.line - _PRELUDE_LINE_COUNT)
    mapped = line_map.get(exp_line) if line_map else None
    file_path = getattr(mapped, "file_path", None) if mapped is not None else getattr(coord, "file", None)
    return CFGSourceLocation(
        file_path=file_path,
        line_number=_map_line(exp_line, line_map),
        column_number=getattr(coord, "column", 0) or 0,
    )


def _value_call_and_target(ast_node):
    kind = type(ast_node).__name__
    value_expr = None
    result_target: Optional[str] = None
    if kind == "Decl" and getattr(ast_node, "init", None) is not None:
        value_expr = ast_node.init
        result_target = str(ast_node.name) if ast_node.name else None
    elif kind == "Assignment":
        value_expr = ast_node.rvalue
        result_target = _format_pycparser_expr(ast_node.lvalue)
    elif kind == "Return" and getattr(ast_node, "expr", None) is not None:
        value_expr = ast_node.expr
        result_target = "return"

    value_call = _unwrap_cast(value_expr)
    if value_call is not None and type(value_call).__name__ == "FuncCall":
        return value_call, result_target
    return None, None


def _call_events(
    ast_node,
    line_map: Optional[Dict[int, Any]],
    function_pointers: Set[str],
) -> Tuple[CFGCall, ...]:
    if ast_node is None:
        return ()

    value_call, result_target = _value_call_and_target(ast_node)
    calls: List[CFGCall] = []

    def visit(node) -> None:
        if node is None:
            return
        if type(node).__name__ == "FuncCall":
            callee_expr = _format_pycparser_expr(node.name)
            syntactic_direct = type(node.name).__name__ == "ID" and callee_expr not in function_pointers
            args = tuple(
                _format_pycparser_expr(arg)
                for arg in (list(getattr(node.args, "exprs", []) or []) if node.args else [])
            )
            calls.append(
                CFGCall(
                    direct_callee=callee_expr if syntactic_direct else None,
                    callee_expression=callee_expr,
                    actual_arguments=args,
                    result_target=result_target if node is value_call else None,
                    source_location=_call_source_location(node, line_map),
                    is_indirect=not syntactic_direct,
                )
            )
        for _, child in node.children():
            visit(child)

    visit(ast_node)
    return tuple(calls)


def _event_payload(
    ast_node,
    alloc_funcs: Optional[Set[str]] = None,
    dealloc_funcs: Optional[Set[str]] = None,
    realloc_funcs: Optional[Set[str]] = None,
    summaries: Optional[Dict[str, FunctionSummary]] = None,
    line_map: Optional[Dict[int, Any]] = None,
):
    """Translate one executable AST node into CFG event facts."""
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

    alloc_set = alloc_funcs if alloc_funcs is not None else {"malloc", "calloc", "realloc", "aligned_alloc"}
    realloc_set = realloc_funcs if realloc_funcs is not None else {"realloc"}

    if summaries:
        def visit_calls(n, curr_target_var=None, is_value_producing=False):
            if n is None:
                return
            if type(n).__name__ == "FuncCall":
                _process_call_effects(
                    n,
                    curr_target_var,
                    summaries,
                    alloc_set,
                    realloc_set,
                    freed,
                    allocated,
                    null_writes,
                    maybe_null_writes,
                    realloc_inputs,
                    realloc_bindings,
                    is_value_producing=is_value_producing,
                )
                for _, child in n.children():
                    visit_calls(child)
            else:
                unwrapped = _unwrap_cast(n)
                for _, child in n.children():
                    visit_calls(
                        child,
                        curr_target_var=curr_target_var,
                        is_value_producing=is_value_producing and child is unwrapped,
                    )

        if kind == "Decl" and ast_node.name and ast_node.init:
            visit_calls(ast_node.init, curr_target_var=str(ast_node.name), is_value_producing=True)
        elif kind == "Assignment":
            lhs_target = list(_assignment_target(ast_node.lvalue))
            visit_calls(
                ast_node.rvalue,
                curr_target_var=lhs_target[0] if lhs_target else None,
                is_value_producing=True,
            )
        elif kind == "FuncCall":
            visit_calls(ast_node)

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
                if call_name in alloc_set or (
                    summaries
                    and summaries.get(call_name)
                    and summaries[call_name].returns_allocation
                ):
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
            if call_name in alloc_set or (
                summaries
                and summaries.get(call_name)
                and summaries[call_name].returns_allocation
            ):
                allocated.update(writes)
                if call_name in realloc_set:
                    for args in _all_calls_args(ast_node.rvalue, call_name):
                        if args:
                            arg1 = _unwrap_cast(args[0])
                            if type(arg1).__name__ == "ID":
                                realloc_inputs.add(str(arg1.name))
                break
        if (
            not allocated
            and writes
            and getattr(ast_node, "op", "=") == "="
            and not _is_nullish(ast_node.rvalue)
        ):
            lhs_unwrapped = _unwrap_cast(ast_node.lvalue)
            rhs_unwrapped = _unwrap_cast(ast_node.rvalue)
            if (
                lhs_unwrapped is not None
                and type(lhs_unwrapped).__name__ == "ID"
                and rhs_unwrapped is not None
                and type(rhs_unwrapped).__name__ == "ID"
            ):
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
    return (
        kind,
        reads,
        writes,
        null_writes,
        maybe_null_writes,
        freed,
        allocated,
        derefs,
        deref_lines,
        asserted,
        alias_writes,
        realloc_inputs,
        realloc_bindings,
    )


__all__ = []
