"""Recognize ensure()-sized buffer returns for CGULL-007.

``ptr = ensure(buf, N)`` promises that a
non-NULL ``ptr`` can be indexed with any subscript strictly less than ``N``.
Only the exact helper name ``ensure`` is recognized.
Writes such as ``ptr[0]``, ``ptr[len + 1]`` after ``ensure(..., len + 3)`` are
therefore safe when the subscript is an affine form dominated by ``N``.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from pycparser import c_ast

from .array_bounds_guards import _integer


ENSURE_NAMES = frozenset({"ensure"})

# pointer name -> (size AST node, null_checked)
EnsureState = Dict[str, Tuple[object, bool]]


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


def _copy_state(state: EnsureState) -> EnsureState:
    return {name: (size, checked) for name, (size, checked) in state.items()}


def _join_states(states: List[EnsureState]) -> EnsureState:
    """Intersect ensure proofs: a fact survives only if every path agrees."""
    if not states:
        return {}
    common = set(states[0])
    for state in states[1:]:
        common.intersection_update(state)
    joined: EnsureState = {}
    for name in common:
        size0, checked0 = states[0][name]
        if all(state[name][0] is size0 and state[name][1] == checked0 for state in states[1:]):
            joined[name] = (size0, checked0)
        elif all(state[name][0] is size0 for state in states[1:]):
            # Same ensure size on all paths; null-checked only if all agree.
            joined[name] = (size0, all(state[name][1] for state in states))
    return joined


def _is_null_constant(node) -> bool:
    node = _unwrap(node)
    if isinstance(node, c_ast.Constant):
        text = str(node.value).lower().rstrip("ul")
        return text in {"0", "0x0"} or node.value == "NULL"
    if isinstance(node, c_ast.ID) and node.name == "NULL":
        return True
    return False


def _null_check_sense(cond, name: str) -> Optional[str]:
    """Return ``'null'`` / ``'nonnull'`` when ``cond`` tests ``name`` for null."""
    cond = _unwrap(cond)
    if isinstance(cond, c_ast.UnaryOp) and cond.op == "!" and isinstance(_unwrap(cond.expr), c_ast.ID):
        if _unwrap(cond.expr).name == name:
            return "null"
    if isinstance(cond, c_ast.ID) and cond.name == name:
        return "nonnull"
    if isinstance(cond, c_ast.BinaryOp) and cond.op in {"==", "!="}:
        left, right = _unwrap(cond.left), _unwrap(cond.right)
        if isinstance(left, c_ast.ID) and left.name == name and _is_null_constant(right):
            return "null" if cond.op == "==" else "nonnull"
        if isinstance(right, c_ast.ID) and right.name == name and _is_null_constant(left):
            return "null" if cond.op == "==" else "nonnull"
    return None


def _mark_null_checked(state: EnsureState, name: str) -> EnsureState:
    if name not in state:
        return state
    size, _ = state[name]
    out = _copy_state(state)
    out[name] = (size, True)
    return out


def _invalidate(state: EnsureState, name: str) -> EnsureState:
    if name not in state:
        return state
    out = _copy_state(state)
    out.pop(name, None)
    return out


def _always_exits(node) -> bool:
    """True when every path through ``node`` returns/gotos (no fall-through)."""
    if node is None:
        return False
    if isinstance(node, (c_ast.Return, c_ast.Goto)):
        return True
    if isinstance(node, c_ast.Compound):
        items = list(node.block_items or [])
        return bool(items) and _always_exits(items[-1])
    if isinstance(node, c_ast.If):
        return _always_exits(node.iftrue) and node.iffalse is not None and _always_exits(node.iffalse)
    return False


def _record_ensure(state: EnsureState, name: str, size) -> EnsureState:
    out = _copy_state(state)
    out[name] = (size, False)
    return out


def collect_ensure_capacities(funcdef, sizeof_env) -> Dict[str, object]:
    """Map pointer names to ensure() size nodes that dominate the whole body.

    Prefer ``ensure_safe_access_keys``, which tracks capacities path-sensitively.
    This helper remains for callers that only need a conservative whole-function
    summary: a name appears only when every path shares the same ensure size.
    """
    # Retained for API compatibility; path-sensitive analysis does not use this
    # as a function-wide suppression map.
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
    """Return (line, column, array_name, index_id) keys proven by ensure().

    Capacities are tracked in statement / CFG order. An access is suppressed
    only when a live ``ensure`` proof dominates it (after a null check when
    required). Pointer reassignment kills the proof; accesses before ``ensure``,
    on other branches, or before the null check are not suppressed.
    """
    if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
        return set()

    from ...ast_analyzer import _extract_identifiers_from_ast, _format_pycparser_expr
    from ...cfg import _PRELUDE_LINE_COUNT, find_function_def

    safe: Set[Tuple[int, int, str, str]] = set()

    for fn in ast_ctx.functions:
        funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
        if funcdef is None:
            continue
        sizeof_env = sizeof_envs.get(fn.name, {})

        def mark_access(node, state: EnsureState) -> None:
            if not isinstance(node.name, c_ast.ID):
                return
            fact = state.get(node.name.name)
            if fact is None:
                return
            size_node, null_checked = fact
            if not null_checked:
                return
            if not proves_subscript_within(node.subscript, size_node, sizeof_env):
                return
            line = (
                node.coord.line - _PRELUDE_LINE_COUNT
                if node.coord
                else fn.start_line
            )
            column = node.coord.column if node.coord else 1
            arr = node.name.name
            indexes = list(_extract_identifiers_from_ast(node.subscript, ignore_callees=True))
            if indexes:
                for index in indexes:
                    safe.add((line, column, arr, index))
            else:
                safe.add((line, column, arr, _format_pycparser_expr(node.subscript)))

        def apply_assignment(state: EnsureState, lvalue, rvalue, op: str) -> EnsureState:
            if not isinstance(lvalue, c_ast.ID):
                return state
            name = lvalue.name
            if op == "=" and _is_ensure_call(rvalue):
                size = _ensure_size_arg(rvalue)
                if size is not None:
                    return _record_ensure(state, name, size)
            # Any write to the pointer kills a prior ensure proof.
            return _invalidate(state, name)

        def walk_expr(node, state: EnsureState) -> EnsureState:
            """Walk expression AST in order; mark safe accesses under ``state``."""
            if node is None:
                return state
            if isinstance(node, c_ast.ArrayRef):
                mark_access(node, state)
                state = walk_expr(node.name, state)
                state = walk_expr(node.subscript, state)
                return state
            if isinstance(node, c_ast.Assignment):
                # RHS then LHS accesses, then the write effect.
                state = walk_expr(node.rvalue, state)
                state = walk_expr(node.lvalue, state)
                return apply_assignment(state, node.lvalue, node.rvalue, node.op)
            if isinstance(node, c_ast.UnaryOp):
                state = walk_expr(node.expr, state)
                if node.op in {"++", "--", "p++", "p--"} and isinstance(node.expr, c_ast.ID):
                    return _invalidate(state, node.expr.name)
                return state
            if isinstance(node, c_ast.FuncCall):
                if node.args:
                    for arg in node.args.exprs or []:
                        state = walk_expr(arg, state)
                return state
            if isinstance(node, c_ast.BinaryOp):
                # Short-circuit: join alternatives conservatively after both sides.
                if node.op in {"&&", "||"}:
                    left_state = walk_expr(node.left, state)
                    right_state = walk_expr(node.right, _copy_state(left_state))
                    return _join_states([left_state, right_state])
                state = walk_expr(node.left, state)
                return walk_expr(node.right, state)
            if isinstance(node, c_ast.TernaryOp):
                state = walk_expr(node.cond, state)
                then_state = walk_expr(node.iftrue, _copy_state(state))
                else_state = walk_expr(node.iffalse, _copy_state(state))
                return _join_states([then_state, else_state])
            if isinstance(node, c_ast.Cast):
                return walk_expr(node.expr, state)
            if isinstance(node, c_ast.ExprList):
                for expr in node.exprs or []:
                    state = walk_expr(expr, state)
                return state
            if isinstance(node, c_ast.StructRef):
                return walk_expr(node.name, state)
            return state

        def walk_stmt(stmt, state: EnsureState) -> EnsureState:
            if stmt is None:
                return state
            if isinstance(stmt, c_ast.Compound):
                return walk_block(stmt.block_items, state)
            if isinstance(stmt, c_ast.Decl):
                if stmt.init is not None:
                    state = walk_expr(stmt.init, state)
                if stmt.name and stmt.init is not None and _is_ensure_call(stmt.init):
                    size = _ensure_size_arg(stmt.init)
                    if size is not None:
                        return _record_ensure(state, stmt.name, size)
                if stmt.name and stmt.init is not None and not _is_ensure_call(stmt.init):
                    # Non-ensure initializer overwrites any prior fact (shadowing).
                    return _invalidate(state, stmt.name)
                return state
            if isinstance(stmt, c_ast.Assignment):
                return walk_expr(stmt, state)
            if isinstance(stmt, c_ast.If):
                state = walk_expr(stmt.cond, state)
                # Refine ensure null-ness per branch before walking bodies so
                # accesses inside ``if (p != 0) { ... }`` / else-of-null see a
                # live proof, while the null path does not.
                refined_then = _copy_state(state)
                refined_else = _copy_state(state)
                for name in list(state):
                    sense = _null_check_sense(stmt.cond, name)
                    if sense == "null":
                        refined_else = _mark_null_checked(refined_else, name)
                    elif sense == "nonnull":
                        refined_then = _mark_null_checked(refined_then, name)

                then_state = walk_stmt(stmt.iftrue, refined_then)
                if stmt.iffalse is not None:
                    else_state = walk_stmt(stmt.iffalse, refined_else)
                else:
                    else_state = refined_else

                # ``if (p == 0) return;`` → fall-through keeps the non-null proof.
                for name in list(state):
                    sense = _null_check_sense(stmt.cond, name)
                    if sense == "null" and _always_exits(stmt.iftrue):
                        else_state = _mark_null_checked(else_state, name)
                    elif (
                        sense == "nonnull"
                        and stmt.iffalse is not None
                        and _always_exits(stmt.iffalse)
                    ):
                        then_state = _mark_null_checked(then_state, name)

                if _always_exits(stmt.iftrue) and stmt.iffalse is not None and _always_exits(
                    stmt.iffalse
                ):
                    return {}
                if _always_exits(stmt.iftrue):
                    return else_state
                if stmt.iffalse is not None and _always_exits(stmt.iffalse):
                    return then_state
                return _join_states([then_state, else_state])
            if isinstance(stmt, (c_ast.While, c_ast.DoWhile, c_ast.For)):
                # Loops: join entry with one conservative body iteration; do not
                # let ensure facts from only some iterations suppress accesses.
                if isinstance(stmt, c_ast.For):
                    if stmt.init is not None:
                        if isinstance(stmt.init, c_ast.DeclList):
                            for decl in stmt.init.decls or []:
                                state = walk_stmt(decl, state)
                        else:
                            state = walk_stmt(stmt.init, state) if isinstance(stmt.init, c_ast.Decl) else walk_expr(stmt.init, state)
                    if stmt.cond is not None:
                        state = walk_expr(stmt.cond, state)
                    body_state = walk_stmt(stmt.stmt, _copy_state(state))
                    if stmt.next is not None:
                        body_state = walk_expr(stmt.next, body_state)
                    return _join_states([state, body_state])
                state = walk_expr(stmt.cond, state) if stmt.cond is not None else state
                body_state = walk_stmt(stmt.stmt, _copy_state(state))
                return _join_states([state, body_state])
            if isinstance(stmt, c_ast.Switch):
                state = walk_expr(stmt.cond, state)
                # Conservative: walk body once and join with entry (fall-through
                # across cases is not modeled precisely).
                body_state = walk_stmt(stmt.stmt, _copy_state(state))
                return _join_states([state, body_state])
            if isinstance(stmt, c_ast.Return):
                if stmt.expr is not None:
                    walk_expr(stmt.expr, state)
                return state
            if isinstance(stmt, (c_ast.Break, c_ast.Continue, c_ast.Goto, c_ast.EmptyStatement)):
                return state
            if isinstance(stmt, c_ast.Label):
                return walk_stmt(stmt.stmt, state)
            if isinstance(stmt, c_ast.Case):
                state = walk_expr(stmt.expr, state) if stmt.expr is not None else state
                for item in stmt.stmts or []:
                    state = walk_stmt(item, state)
                return state
            if isinstance(stmt, c_ast.Default):
                for item in stmt.stmts or []:
                    state = walk_stmt(item, state)
                return state
            # Generic statement: walk child expressions/statements.
            if isinstance(stmt, c_ast.FuncCall):
                return walk_expr(stmt, state)
            if isinstance(stmt, c_ast.UnaryOp):
                return walk_expr(stmt, state)
            if isinstance(stmt, c_ast.BinaryOp):
                return walk_expr(stmt, state)
            if isinstance(stmt, c_ast.TernaryOp):
                return walk_expr(stmt, state)
            if isinstance(stmt, c_ast.Cast):
                return walk_expr(stmt, state)
            if isinstance(stmt, c_ast.ExprList):
                return walk_expr(stmt, state)
            for _, child in stmt.children():
                if isinstance(child, (c_ast.Compound, c_ast.If, c_ast.For, c_ast.While, c_ast.DoWhile)):
                    state = walk_stmt(child, state)
                else:
                    state = walk_expr(child, state)
            return state

        def walk_block(items, state: EnsureState) -> EnsureState:
            for item in items or []:
                state = walk_stmt(item, state)
            return state

        if funcdef.body is not None:
            walk_block(funcdef.body.block_items, {})

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


def _body_breaks_induction(body, index: str) -> bool:
    """True when the loop body mutates ``index`` or escapes via break/goto."""
    if body is None:
        return False
    if _index_written(body, index):
        return True

    escaped = False

    class EscapeFinder(c_ast.NodeVisitor):
        def visit_Break(self, n):
            nonlocal escaped
            escaped = True

        def visit_Goto(self, n):
            nonlocal escaped
            escaped = True

        def visit_For(self, n):
            return

        def visit_While(self, n):
            return

        def visit_DoWhile(self, n):
            return

        def visit_Switch(self, n):
            # ``break`` inside switch does not exit the surrounding for-loop.
            return

    EscapeFinder().visit(body)
    return escaped


def sizeof_for_loop_safe_keys(ast_ctx, sizeof_envs, capacities_by_fn) -> Set[Tuple[int, int, str, str]]:
    """Prove ``arr[i]`` after ``for (i = 0; i < N; i++)`` when ``N < capacity(arr)``.

    Unit-increment zero-initialized counters exit with ``i <= N`` only when the
    body does not write the counter or escape via ``break``/``goto``. Later
    statements are processed in order so a write to ``i`` invalidates the proof
    before subsequent accesses are marked safe.
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

        def mark_array_refs_ordered(root, index, exclusive_bound):
            """Mark ``arr[index]`` safe until ``index`` is written (CFG order)."""
            live = True

            def mark_if_safe(node):
                nonlocal live
                if not live:
                    return
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

            def kill_if_write_lvalue(lvalue):
                nonlocal live
                if isinstance(lvalue, c_ast.ID) and lvalue.name == index:
                    live = False

            def walk(node):
                nonlocal live
                if node is None or not live:
                    return
                if isinstance(node, (c_ast.For, c_ast.While, c_ast.DoWhile)):
                    return
                if isinstance(node, c_ast.Compound):
                    for item in node.block_items or []:
                        walk(item)
                        if not live:
                            return
                    return
                if isinstance(node, c_ast.Assignment):
                    walk(node.rvalue)
                    # Accesses in the LHS (e.g. arr[i] = ...) use the pre-write index.
                    if isinstance(node.lvalue, c_ast.ArrayRef):
                        mark_if_safe(node.lvalue)
                        walk(node.lvalue.name)
                        walk(node.lvalue.subscript)
                    else:
                        walk(node.lvalue)
                    kill_if_write_lvalue(node.lvalue)
                    return
                if isinstance(node, c_ast.UnaryOp):
                    walk(node.expr)
                    if node.op in {"++", "--", "p++", "p--"} and isinstance(node.expr, c_ast.ID):
                        if node.expr.name == index:
                            live = False
                    return
                if isinstance(node, c_ast.ArrayRef):
                    mark_if_safe(node)
                    walk(node.name)
                    walk(node.subscript)
                    return
                if isinstance(node, c_ast.Decl):
                    if node.init is not None:
                        walk(node.init)
                    if node.name == index:
                        live = False
                    return
                if isinstance(node, c_ast.If):
                    walk(node.cond)
                    # Conservatively require the proof to survive both branches.
                    # Mark accesses in both; kill if either writes the index.
                    before = live
                    walk(node.iftrue)
                    then_live = live
                    live = before
                    if node.iffalse is not None:
                        walk(node.iffalse)
                    else_live = live
                    live = then_live and else_live
                    return
                for _, child in node.children():
                    walk(child)

            walk(root)

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
                        and not _body_breaks_induction(stmt.stmt, index)
                    ):
                        for later in items[idx + 1 :]:
                            # Process in order: writes invalidate before later accesses.
                            mark_array_refs_ordered(later, index, bound)
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
