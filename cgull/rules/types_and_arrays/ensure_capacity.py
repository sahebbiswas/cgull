"""Recognize ensure()/realloc-sized buffer returns for CGULL-007.

``ptr = ensure(buf, N)`` (and similarly named helpers) promises that a
non-NULL ``ptr`` can be indexed with any subscript strictly less than ``N``.
Writes such as ``ptr[0]``, ``ptr[len + 1]`` after ``ensure(..., len + 3)`` are
therefore safe when the subscript is an affine form dominated by ``N``.
"""

from __future__ import annotations

from typing import Dict, Optional, Set, Tuple

from pycparser import c_ast

from .array_bounds_guards import _integer


ENSURE_NAMES = frozenset({"ensure"})


def _unwrap(node):
    while isinstance(node, c_ast.Cast):
        node = node.expr
    return node


def _affine(node, sizeof_env) -> Optional[Tuple[Optional[str], int]]:
    """Return ``(symbol_or_None, offset)`` for ``symbol + offset`` forms."""
    node = _unwrap(node)
    value = _integer(node, sizeof_env)
    if value is not None:
        return None, value
    if isinstance(node, c_ast.ID):
        return node.name, 0
    if isinstance(node, c_ast.BinaryOp) and node.op in {"+", "-"}:
        if isinstance(node.left, c_ast.ID):
            amount = _integer(node.right, sizeof_env)
            if amount is not None:
                return node.left.name, amount if node.op == "+" else -amount
        if node.op == "+" and isinstance(node.right, c_ast.ID):
            amount = _integer(node.left, sizeof_env)
            if amount is not None:
                return node.right.name, amount
        # size_t cast wrappers already unwrapped; handle ``(size_t)length + K``
        left = _unwrap(node.left)
        right = _unwrap(node.right)
        if isinstance(left, c_ast.ID):
            amount = _integer(right, sizeof_env)
            if amount is not None:
                return left.name, amount if node.op == "+" else -amount
        if node.op == "+" and isinstance(right, c_ast.ID):
            amount = _integer(left, sizeof_env)
            if amount is not None:
                return right.name, amount
    return None


def proves_subscript_within(subscript, size_node, sizeof_env) -> bool:
    """Return True when ``subscript`` is strictly less than ``size_node``."""
    sub = _affine(subscript, sizeof_env)
    size = _affine(size_node, sizeof_env)
    if sub is None or size is None:
        return False
    sub_sym, sub_off = sub
    size_sym, size_off = size
    if sub_sym != size_sym:
        return False
    return sub_off < size_off


def _is_ensure_call(node) -> bool:
    node = _unwrap(node)
    if not isinstance(node, c_ast.FuncCall):
        return False
    name = node.name
    if isinstance(name, c_ast.ID):
        return name.name in ENSURE_NAMES
    return False


def _ensure_size_arg(node):
    node = _unwrap(node)
    if not isinstance(node, c_ast.FuncCall) or node.args is None:
        return None
    args = list(node.args.exprs or [])
    return args[1] if len(args) >= 2 else (args[0] if len(args) == 1 else None)


def collect_ensure_capacities(funcdef, sizeof_env) -> Dict[str, object]:
    """Map pointer names to the size AST node from their latest ensure() def."""
    capacities: Dict[str, object] = {}

    class Visitor(c_ast.NodeVisitor):
        def visit_Assignment(self, node):
            if node.op == "=" and isinstance(node.lvalue, c_ast.ID) and _is_ensure_call(node.rvalue):
                size = _ensure_size_arg(node.rvalue)
                if size is not None:
                    capacities[node.lvalue.name] = size
            self.generic_visit(node)

        def visit_Decl(self, node):
            if node.name and node.init is not None and _is_ensure_call(node.init):
                size = _ensure_size_arg(node.init)
                if size is not None:
                    capacities[node.name] = size
            self.generic_visit(node)

    Visitor().visit(funcdef)
    return capacities


def ensure_safe_access_keys(ast_ctx, sizeof_envs) -> Set[Tuple[int, int, str, str]]:
    """Return (line, column, array_name, index_id) keys proven by ensure()."""
    if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
        return set()

    from ...ast_analyzer import _extract_identifiers_from_ast, _format_pycparser_expr
    from ...cfg import _PRELUDE_LINE_COUNT, find_function_def

    safe = set()
    for fn in ast_ctx.functions:
        funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
        if funcdef is None:
            continue
        sizeof_env = sizeof_envs.get(fn.name, {})
        capacities = collect_ensure_capacities(funcdef, sizeof_env)
        if not capacities:
            continue

        class AccessVisitor(c_ast.NodeVisitor):
            def visit_ArrayRef(v_self, node):
                if isinstance(node.name, c_ast.ID) and node.name.name in capacities:
                    size_node = capacities[node.name.name]
                    if proves_subscript_within(node.subscript, size_node, sizeof_env):
                        line = (
                            node.coord.line - _PRELUDE_LINE_COUNT
                            if node.coord
                            else fn.start_line
                        )
                        column = node.coord.column if node.coord else 1
                        arr = node.name.name
                        for index in _extract_identifiers_from_ast(node.subscript, ignore_callees=True):
                            safe.add((line, column, arr, index))
                        # Constant-only subscripts still suppress via empty index set;
                        # record a synthetic key using the formatted subscript.
                        if not _extract_identifiers_from_ast(node.subscript, ignore_callees=True):
                            safe.add((line, column, arr, _format_pycparser_expr(node.subscript)))
                v_self.generic_visit(node)

        AccessVisitor().visit(funcdef)
    return safe


def _for_bound_and_index(cond, sizeof_env):
    """Return (index_name, exclusive_bound) for ``i < N`` / ``(i < N) && ...``."""
    if isinstance(cond, c_ast.BinaryOp) and cond.op == "&&":
        return _for_bound_and_index(cond.left, sizeof_env)
    if not isinstance(cond, c_ast.BinaryOp) or cond.op != "<":
        return None, None
    left = _unwrap(cond.left)
    if not isinstance(left, c_ast.ID):
        return None, None
    bound = _integer(cond.right, sizeof_env)
    return (left.name, bound) if bound is not None else (None, None)


def _is_unit_increment(next_node, index: str) -> bool:
    if next_node is None:
        return False
    if isinstance(next_node, c_ast.UnaryOp) and next_node.op in {"++", "p++"}:
        return isinstance(next_node.expr, c_ast.ID) and next_node.expr.name == index
    if isinstance(next_node, c_ast.Assignment) and next_node.op == "+=":
        if isinstance(next_node.lvalue, c_ast.ID) and next_node.lvalue.name == index:
            return _integer(next_node.rvalue, {}) == 1
    return False


def _is_zero_init(init_node, index: str) -> bool:
    if init_node is None:
        return False
    if isinstance(init_node, c_ast.Assignment) and init_node.op == "=":
        if isinstance(init_node.lvalue, c_ast.ID) and init_node.lvalue.name == index:
            return _integer(init_node.rvalue, {}) == 0
    if isinstance(init_node, c_ast.DeclList):
        return any(_is_zero_init(decl, index) for decl in (init_node.decls or []))
    if isinstance(init_node, c_ast.Decl) and init_node.name == index and init_node.init is not None:
        return _integer(init_node.init, {}) == 0
    return False


def _index_written(node, index: str) -> bool:
    written = False

    class Finder(c_ast.NodeVisitor):
        def visit_Assignment(self, n):
            nonlocal written
            if isinstance(n.lvalue, c_ast.ID) and n.lvalue.name == index:
                written = True
            self.generic_visit(n)

        def visit_UnaryOp(self, n):
            nonlocal written
            if n.op in {"++", "--", "p++", "p--"} and isinstance(n.expr, c_ast.ID):
                if n.expr.name == index:
                    written = True
            self.generic_visit(n)

    Finder().visit(node)
    return written


def sizeof_for_loop_safe_keys(ast_ctx, sizeof_envs, capacities_by_fn) -> Set[Tuple[int, int, str, str]]:
    """Prove ``arr[i]`` after ``for (i = 0; i < N; i++)`` when ``N < capacity(arr)``.

    Unit-increment zero-initialized counters exit with ``i <= N``. Early
    ``goto`` labels that appear as the next statements in the same compound
    are included until ``i`` is overwritten.
    """
    if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
        return set()

    from ...cfg import _PRELUDE_LINE_COUNT, find_function_def

    safe: Set[Tuple[int, int, str, str]] = set()

    for fn in ast_ctx.functions:
        funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
        if funcdef is None:
            continue
        sizeof_env = sizeof_envs.get(fn.name, {})
        arr_caps = capacities_by_fn.get(fn.name, {})

        def mark_array_refs(root, index, exclusive_bound, *, stop_at_nested_loops=True):
            class Walker(c_ast.NodeVisitor):
                def visit_ArrayRef(self, node):
                    if (
                        isinstance(node.subscript, c_ast.ID)
                        and node.subscript.name == index
                        and isinstance(node.name, c_ast.ID)
                    ):
                        cap = arr_caps.get(node.name.name)
                        if cap is not None and exclusive_bound < cap:
                            line = (
                                node.coord.line - _PRELUDE_LINE_COUNT
                                if node.coord
                                else fn.start_line
                            )
                            column = node.coord.column if node.coord else 1
                            safe.add((line, column, node.name.name, index))
                    self.generic_visit(node)

                def visit_For(self, node):
                    if stop_at_nested_loops:
                        return
                    self.generic_visit(node)

                def visit_While(self, node):
                    if stop_at_nested_loops:
                        return
                    self.generic_visit(node)

                def visit_DoWhile(self, node):
                    if stop_at_nested_loops:
                        return
                    self.generic_visit(node)

            Walker().visit(root)

        def handle_compound(items):
            items = list(items or [])
            for idx, stmt in enumerate(items):
                if isinstance(stmt, c_ast.For):
                    index, bound = _for_bound_and_index(stmt.cond, sizeof_env)
                    if (
                        index
                        and bound is not None
                        and _is_zero_init(stmt.init, index)
                        and _is_unit_increment(stmt.next, index)
                    ):
                        for later in items[idx + 1 :]:
                            mark_array_refs(later, index, bound)
                            if _index_written(later, index):
                                break
                if isinstance(stmt, c_ast.Compound):
                    handle_compound(stmt.block_items)
                else:
                    for _, child in stmt.children():
                        if isinstance(child, c_ast.Compound):
                            handle_compound(child.block_items)

        if funcdef.body is not None:
            handle_compound(funcdef.body.block_items)

    return safe
