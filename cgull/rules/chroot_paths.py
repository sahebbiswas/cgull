"""Success-path working-directory obligations for CGULL-039.

Each query assumes one particular chroot succeeds (returns zero). Unknown
predicates fork; only evaluated chdir("/") calls discharge the obligation.
The finite state tracks simple result bindings, never guesses helper effects.
"""

from collections import deque
from dataclasses import dataclass, replace
from functools import lru_cache

from pycparser import c_ast


@dataclass(frozen=True)
class State:
    pending: bool = False
    values: tuple = ()

    def bind(self, name, value):
        values = dict(self.values)
        values.pop(name, None)
        if value is not None:
            values[name] = value
        return replace(self, values=tuple(sorted(values.items())))


def expression(event):
    node = getattr(event, "_ast_node", None)
    if event.kind in {"label", "goto", "unknown_control_flow", "break", "continue"}:
        return None
    if isinstance(
        node, (c_ast.If, c_ast.While, c_ast.DoWhile, c_ast.For, c_ast.Switch)
    ):
        return node.cond
    return node


def calls_in(node):
    if node is None:
        return
    if isinstance(node, c_ast.UnaryOp) and node.op == "sizeof":
        return
    if isinstance(node, c_ast.FuncCall):
        yield node
    for _, child in node.children():
        yield from calls_in(child)


def callee(node):
    return node.name.name if isinstance(node.name, c_ast.ID) else None


def unsafe_success_path(cfg, target, untracked_names=frozenset()):
    """Whether a reachable successful invocation can continue without chdir."""
    unsafe = False

    @lru_cache(maxsize=4096)
    def evaluate(node, state):
        # Merge identical expression alternatives before composing operands.
        return tuple(dict.fromkeys(evaluate_uncached(node, state)))

    def evaluate_uncached(node, state):
        nonlocal unsafe
        if node is None:
            return [(state, None)]
        if isinstance(node, c_ast.ID):
            return [
                (
                    state,
                    (
                        dict(state.values).get(node.name)
                        if node.name not in untracked_names
                        else None
                    ),
                )
            ]
        if isinstance(node, c_ast.Constant):
            try:
                value = int(node.value, 0) if node.type == "int" else None
            except ValueError:
                value = None
            return [(state, value)]
        if isinstance(node, c_ast.UnaryOp):
            if node.op == "sizeof":
                return [(state, None)]
            results = evaluate(node.expr, state)
            if node.op in {"p++", "p--", "++", "--", "&"}:
                return [
                    (
                        (
                            s.bind(node.expr.name, None)
                            if isinstance(node.expr, c_ast.ID)
                            else replace(s, values=())
                        ),
                        None,
                    )
                    for s, _ in results
                ]
            ops = {"!": lambda v: int(not v), "-": lambda v: -v, "+": lambda v: v}
            return [
                (s, ops[node.op](v) if v is not None and node.op in ops else None)
                for s, v in results
            ]
        if isinstance(node, (c_ast.Assignment, c_ast.Decl)):
            if isinstance(node, c_ast.Decl):
                rhs, name, simple = node.init, node.name, True
            else:
                rhs = node.rvalue
                name = node.lvalue.name if isinstance(node.lvalue, c_ast.ID) else None
                simple = node.op == "="
            results = []
            for out, value in evaluate(rhs, state):
                value = value if simple else None
                out = out.bind(name, value) if name else replace(out, values=())
                results.append((out, value))
            return results
        if isinstance(node, c_ast.BinaryOp):
            results = []
            # C does not sequence ordinary binary operands. A repair in the
            # other operand cannot establish that it follows this chroot.
            if node.op not in {"&&", "||"}:
                left_calls, right_calls = list(calls_in(node.left)), list(
                    calls_in(node.right)
                )
                if (
                    target in left_calls
                    and any(callee(c) == "chdir" for c in right_calls)
                ) or (
                    target in right_calls
                    and any(callee(c) == "chdir" for c in left_calls)
                ):
                    unsafe = True
                if state.pending and (
                    (
                        any(callee(c) == "chdir" for c in left_calls)
                        and any(callee(c) != "chdir" for c in right_calls)
                    )
                    or (
                        any(callee(c) == "chdir" for c in right_calls)
                        and any(callee(c) != "chdir" for c in left_calls)
                    )
                ):
                    unsafe = True
            for s, left in evaluate(node.left, state):
                if node.op in {"&&", "||"}:
                    for truth in (False, True) if left is None else (bool(left),):
                        if truth == (node.op == "||"):
                            results.append((s, int(truth)))
                        else:
                            results.extend(
                                (t, None if right is None else int(bool(right)))
                                for t, right in evaluate(node.right, s)
                            )
                else:
                    for t, right in evaluate(node.right, s):
                        ops = {
                            "==": lambda: left == right,
                            "!=": lambda: left != right,
                            "<": lambda: left < right,
                            "<=": lambda: left <= right,
                            ">": lambda: left > right,
                            ">=": lambda: left >= right,
                        }
                        value = (
                            int(ops[node.op]())
                            if left is not None and right is not None and node.op in ops
                            else None
                        )
                        results.append((t, value))
            return results
        if isinstance(node, c_ast.TernaryOp):
            results = []
            for s, value in evaluate(node.cond, state):
                for truth in (False, True) if value is None else (bool(value),):
                    results.extend(evaluate(node.iftrue if truth else node.iffalse, s))
            return results
        if isinstance(node, c_ast.FuncCall):
            arguments = node.args.exprs if node.args else ()
            argument_calls = [list(calls_in(arg)) for arg in arguments]
            if any(target in group for group in argument_calls) and any(
                callee(c) == "chdir" for group in argument_calls for c in group
            ):
                unsafe = True
            if (
                state.pending
                and any(callee(c) == "chdir" for group in argument_calls for c in group)
                and any(callee(c) != "chdir" for group in argument_calls for c in group)
            ):
                unsafe = True
            states = [(state, None)]
            for arg in node.args.exprs if node.args else ():
                states = [result for s, _ in states for result in evaluate(arg, s)]
            results = []
            for s, _ in states:
                if node is target:
                    unsafe |= s.pending
                    results.append((replace(s, pending=True, values=()), 0))
                elif (
                    callee(node) == "chdir"
                    and node.args
                    and len(node.args.exprs) == 1
                    and isinstance(node.args.exprs[0], c_ast.Constant)
                    and node.args.exprs[0].type == "string"
                    and node.args.exprs[0].value == '"/"'
                ):
                    results.append((replace(s, pending=False, values=()), None))
                else:
                    # Calls are security-sensitive continuation, including an
                    # additional chroot; no undocumented helper is a repair.
                    unsafe |= s.pending
                    results.append((replace(s, values=()), None))
            return results
        # Comma lists and returns evaluate their expressions. Unsupported
        # constructs retain obligations and discard any inferred result.
        results = [(state, None)]
        for _, child in node.children():
            results = [r for s, _ in results for r in evaluate(child, s)]
        return [
            (s, v if isinstance(node, (c_ast.ExprList, c_ast.Return)) else None)
            for s, v in results
        ]

    start = (cfg.entry, State())
    queue = deque([start])
    seen = set()
    pending_edges = {}
    while queue:
        key = queue.popleft()
        if key in seen:
            continue
        seen.add(key)
        # Bound path-state explosion, conservatively retaining the finding.
        if len(seen) > max(1024, 32 * len(cfg.nodes)):
            return True
        node_id, state = key
        event = cfg.nodes[node_id]
        if event.kind == "unknown_control_flow" and state.pending:
            return True
        for out, value in evaluate(expression(event), state):
            if unsafe or (out.pending and not event.successors):
                return True
            for successor in event.successors:
                truth = cfg.edge_truth.get((node_id, successor))
                if truth is not None and value is not None and bool(value) != truth:
                    continue
                next_key = (successor, out)
                queue.append(next_key)
                if state.pending and out.pending:
                    pending_edges.setdefault(key, set()).add(next_key)
    # A cycle with a continuously pending obligation can avoid repair forever.
    indegree = {}
    for key, successors in pending_edges.items():
        indegree.setdefault(key, 0)
        for successor in successors:
            indegree[successor] = indegree.get(successor, 0) + 1
    queue = deque(key for key, degree in indegree.items() if degree == 0)
    while queue:
        key = queue.popleft()
        indegree.pop(key)
        for successor in pending_edges.get(key, ()):
            indegree[successor] -= 1
            if indegree[successor] == 0:
                queue.append(successor)
    return bool(indegree)
