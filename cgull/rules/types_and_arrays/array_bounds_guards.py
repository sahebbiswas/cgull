"""Ordered, conservative AST bounds proofs for CGULL-007.

Facts are separate lower/upper bound proofs. Short-circuit alternatives join
by intersection; mutations and calls discard proofs before later operands.
Simple affine CFG facts allow a bound on one induction variable to prove a
bound on an index that is lockstep-related to it.
"""

from collections import deque
import re
from typing import Optional, Union

from pycparser import c_ast

from ...cfg.affine_relations import AffineFacts, join_affine, transfer_affine


Capacity = Optional[Union[int, str]]


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


def _contains_call(node):
    if node is None:
        return False
    if isinstance(node, c_ast.FuncCall):
        return True
    return any(_contains_call(child) for _, child in node.children())


def _writes_symbol(event, symbol: Optional[str]) -> bool:
    return bool(symbol and symbol in getattr(event, "writes", set()))


def guarded_access(cfg, target_id, access, index, capacity: Capacity, signed):
    """Prove both bounds at this exact access on every reachable CFG path.

    ``capacity`` is either a concrete element count or the name of a scalar
    whose value is explicitly contracted to be the indexed object's element
    capacity. Unknown pointer extents are represented by ``None`` and do not
    make arbitrary symbolic comparisons into bounds proofs.

    The relational component records must-hold facts such as ``i == y + C``.
    They are joined by intersection at CFG merge points, so path-dependent or
    divergent loop updates cannot accidentally suppress a finding.
    """
    if cfg.entry is None or target_id is None:
        return False
    # A bound on A alone does not prove A + offset or a cast is in range.
    if not isinstance(access.subscript, c_ast.ID) or access.subscript.name != index:
        return False

    capacity_symbol = capacity if isinstance(capacity, str) else None
    initial = (not signed, False, AffineFacts())

    def join(a, b):
        return (a[0] and b[0], a[1] and b[1], join_affine(a[2], b[2]))

    def reset_bounds(facts, *, clear_relations=False):
        return (not signed, False, AffineFacts() if clear_relations else facts[2])

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
        if _contains_call(expr) or _effects(expr, index):
            return reset_bounds(facts, clear_relations=True)
        if not isinstance(expr, c_ast.BinaryOp):
            return facts

        left, right, op = expr.left, expr.right, expr.op
        if not truth:
            op = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}.get(op, "")

        affine = facts[2]
        candidate = None
        offset = 0
        if isinstance(left, c_ast.ID):
            relation = affine.offset(index, left.name)
            if relation is not None:
                candidate, offset = left.name, relation
        if candidate is None and isinstance(right, c_ast.ID):
            relation = affine.offset(index, right.name)
            if relation is not None:
                left, right = right, left
                op = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}.get(op, op)
                candidate, offset = left.name, relation
        if candidate is None:
            return facts

        lower, upper, _ = facts
        limit = _integer(right)
        if limit is None:
            if (
                capacity_symbol is not None
                and isinstance(right, c_ast.ID)
                and right.name == capacity_symbol
                and op == "<"
                and offset <= 0
            ):
                return lower, True, affine
            return facts
        if not signed and limit < 0:
            # Usual arithmetic conversions can turn a negative limit into
            # a large unsigned value; do not interpret it as a small bound.
            return facts

        translated = limit + offset
        if op in {">=", ">", "=="}:
            lower |= translated + (op == ">") >= 0
        if op in {"<", "<=", "=="}:
            # For i == y + C, y < L proves i < capacity exactly when
            # L + C <= capacity (and similarly for <= / ==).
            upper |= isinstance(capacity, int) and translated + (op != "<") <= capacity
        return lower, upper, affine

    def at_access(expr, facts):
        if expr is None:
            return None
        if expr is access:
            # Side effects within a subscript are not covered by an ID proof.
            return reset_bounds(facts, clear_relations=True) if _effects(expr.subscript, index) else facts
        if isinstance(expr, c_ast.BinaryOp) and expr.op in {"&&", "||"}:
            found = at_access(expr.left, facts)
            if found is not None:
                return found
            return at_access(expr.right, refine(expr.left, expr.op == "&&", facts))
        if isinstance(expr, c_ast.FuncCall):
            # The call occurs after its arguments; only argument/callee
            # side effects can invalidate a proof at an argument access.
            child_facts = reset_bounds(facts, clear_relations=True) if (
                _effects(expr.args, index) or _effects(expr.name, index)
            ) else facts
            found = at_access(expr.name, child_facts)
            return found if found is not None else at_access(expr.args, child_facts)
        if isinstance(expr, c_ast.TernaryOp):
            found = at_access(expr.cond, facts)
            if found is not None:
                return found
            for arm, arm_truth in ((expr.iftrue, True), (expr.iffalse, False)):
                found = at_access(arm, refine(expr.cond, arm_truth, facts))
                if found is not None:
                    return found
            return None
        # Other operand evaluation orders are not assumed. Any side effect
        # could precede the access, so conservatively invalidate incoming facts.
        child_facts = reset_bounds(facts, clear_relations=True) if _effects(expr, index) else facts
        for _, child in expr.children():
            found = at_access(child, child_facts)
            if found is not None:
                return found
        return None

    queue = deque([(cfg.entry, initial)])
    in_states = {}
    reached = False
    while queue:
        node_id, incoming = queue.popleft()
        previous = in_states.get(node_id)
        facts = incoming if previous is None else join(previous, incoming)
        if previous == facts:
            continue
        in_states[node_id] = facts

        event = cfg.nodes[node_id]
        expr = event_expression(event)
        if node_id == target_id:
            reached = True
            proof = at_access(expr, facts)
            if proof is None or not all(proof[:2]):
                return False
            # Continue through the target to verify later loop iterations.

        if event.kind.endswith("_cond"):
            for successor in event.successors:
                edge_truth = cfg.edge_truth.get((node_id, successor))
                out = refine(expr, edge_truth, facts) if edge_truth is not None else join(
                    refine(expr, True, facts), refine(expr, False, facts)
                )
                queue.append((successor, out))
            continue

        affine = transfer_affine(
            getattr(event, "_ast_node", None),
            getattr(event, "writes", set()),
            facts[2],
            has_unknown_call=bool(getattr(event, "calls", ())) or _contains_call(expr),
        )
        if index in event.writes or _effects(expr, index):
            out = (not signed, False, affine)
        elif _writes_symbol(event, capacity_symbol):
            # Reassigning the contracted length invalidates the upper proof.
            out = (facts[0], False, affine)
        else:
            out = (facts[0], facts[1], affine)
        queue.extend((successor, out) for successor in event.successors)
    return reached
