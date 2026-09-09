"""Ordered, conservative AST bounds proofs for CGULL-007.

Facts are separate lower/upper bound proofs. Short-circuit alternatives join
by intersection; mutations and calls discard proofs before later operands.
"""

from collections import deque
import re

from pycparser import c_ast


def event_expression(event):
    node = getattr(event, "_ast_node", None)
    if isinstance(node, (c_ast.If, c_ast.While, c_ast.DoWhile, c_ast.For, c_ast.Switch)):
        return node.cond
    return node


def access_events(cfg):
    """Associate accesses by AST identity, including multiline conditions."""
    result = {}

    def walk(node, event_id):
        if node is None:
            return
        if isinstance(node, c_ast.ArrayRef):
            result[id(node)] = event_id
        for _, child in node.children():
            walk(child, event_id)

    for event_id, event in cfg.nodes.items():
        walk(event_expression(event), event_id)
    return result


def _integer(node):
    if isinstance(node, c_ast.Constant) and node.type == "int":
        token = re.sub(r"[uUlL]+$", "", node.value)
        try:
            return int(token, 8 if len(token) > 1 and token.startswith("0") and token.isdigit() else 0)
        except ValueError:
            return None
    if isinstance(node, c_ast.UnaryOp) and node.op in {"+", "-"}:
        value = _integer(node.expr)
        return None if value is None else value if node.op == "+" else -value
    if isinstance(node, c_ast.BinaryOp) and node.op in {"+", "-", "*"}:
        left, right = _integer(node.left), _integer(node.right)
        if left is not None and right is not None:
            return {"+": lambda: left + right, "-": lambda: left - right,
                    "*": lambda: left * right}[node.op]()
    return None


def _effects(node, index):
    if node is None:
        return False
    if isinstance(node, c_ast.FuncCall):
        return True
    if isinstance(node, c_ast.Assignment) and isinstance(node.lvalue, c_ast.ID) and node.lvalue.name == index:
        return True
    if isinstance(node, c_ast.UnaryOp) and node.op in {"++", "--", "p++", "p--"}:
        if isinstance(node.expr, c_ast.ID) and node.expr.name == index:
            return True
    return any(_effects(child, index) for _, child in node.children())


def guarded_access(cfg, target_id, access, index, capacity, signed):
    """Prove both bounds at this exact access on every reachable CFG path."""
    if cfg.entry is None or target_id is None:
        return False
    # A bound on A alone does not prove A + offset or a cast is in range.
    if not isinstance(access.subscript, c_ast.ID) or access.subscript.name != index:
        return False
    empty = (not signed, False)

    def join(a, b):
        return (a[0] and b[0], a[1] and b[1])

    def refine(expr, truth, facts):
        if expr is None:
            return facts
        if isinstance(expr, c_ast.UnaryOp) and expr.op == "!":
            return refine(expr.expr, not truth, facts)
        if isinstance(expr, c_ast.BinaryOp) and expr.op in {"&&", "||"}:
            left_truth = expr.op == "&&"
            through = refine(expr.right, truth, refine(expr.left, left_truth, facts))
            if truth == left_truth:
                return through
            return join(refine(expr.left, truth, facts), through)
        if _effects(expr, index):
            return empty
        if not isinstance(expr, c_ast.BinaryOp):
            return facts
        left, right, op = expr.left, expr.right, expr.op
        if isinstance(right, c_ast.ID) and right.name == index:
            left, right = right, left
            op = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}.get(op, op)
        if not isinstance(left, c_ast.ID) or left.name != index:
            return facts
        if not truth:
            op = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}.get(op, "")
        lower, upper = facts
        limit = _integer(right)
        if limit is None:
            # An external pointer's unknown extent retains the historical
            # explicit symbolic-check policy. This cannot prove a check
            # against a known array/heap capacity.
            if capacity is None and isinstance(right, c_ast.ID) and op in {"<", "<="}:
                return lower, True
            return facts
        if not signed and limit < 0:
            # Usual arithmetic conversions can turn a negative limit into
            # a large unsigned value; do not interpret it as a small bound.
            return facts
        if op in {">=", ">", "=="}:
            lower |= limit + (op == ">") >= 0
        if op in {"<", "<=", "=="}:
            # Preserve explicit-check recognition for pointers whose extent
            # is unknown; known extents always require a compatible limit.
            upper |= capacity is None or limit + (op != "<") <= capacity
        return lower, upper

    def at_access(expr, facts):
        if expr is None:
            return None
        if expr is access:
            # Side effects within a subscript are not covered by an ID proof.
            return empty if _effects(expr.subscript, index) else facts
        if isinstance(expr, c_ast.BinaryOp) and expr.op in {"&&", "||"}:
            found = at_access(expr.left, facts)
            if found is not None:
                return found
            return at_access(expr.right, refine(expr.left, expr.op == "&&", facts))
        if isinstance(expr, c_ast.FuncCall):
            # The call occurs after its arguments; only argument/callee
            # side effects can invalidate a proof at an argument access.
            child_facts = empty if (_effects(expr.args, index) or _effects(expr.name, index)) else facts
            found = at_access(expr.name, child_facts)
            return found if found is not None else at_access(expr.args, child_facts)
        if isinstance(expr, c_ast.TernaryOp):
            found = at_access(expr.cond, facts)
            if found is not None:
                return found
            for arm, truth in ((expr.iftrue, True), (expr.iffalse, False)):
                found = at_access(arm, refine(expr.cond, truth, facts))
                if found is not None:
                    return found
            return None
        # Other operand evaluation orders are not assumed. Any side effect
        # could precede the access, so conservatively invalidate incoming facts.
        child_facts = empty if _effects(expr, index) else facts
        for _, child in expr.children():
            found = at_access(child, child_facts)
            if found is not None:
                return found
        return None

    queue = deque([(cfg.entry, empty)])
    visited = set()
    reached = False
    while queue:
        node_id, facts = queue.popleft()
        if (node_id, facts) in visited:
            continue
        visited.add((node_id, facts))
        event = cfg.nodes[node_id]
        expr = event_expression(event)
        if node_id == target_id:
            reached = True
            proof = at_access(expr, facts)
            if proof is None or not all(proof):
                return False
            # Continue through the target to check subsequent loop iterations.
        if event.kind.endswith("_cond"):
            for successor in event.successors:
                truth = cfg.edge_truth.get((node_id, successor))
                out = refine(expr, truth, facts) if truth is not None else (
                    join(refine(expr, True, facts), refine(expr, False, facts)))
                queue.append((successor, out))
        else:
            out = empty if index in event.writes or _effects(expr, index) else facts
            queue.extend((successor, out) for successor in event.successors)
    return reached
