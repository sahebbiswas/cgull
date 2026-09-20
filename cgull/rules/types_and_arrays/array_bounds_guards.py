"""Ordered, conservative AST bounds proofs for CGULL-007.

Facts are separate lower/upper bound proofs. Short-circuit alternatives join
by intersection; mutations and calls discard proofs before later operands.
Simple affine CFG facts allow a bound on one induction variable to prove a
bound on an index that is lockstep-related to it.

Also recognizes:
- ``sizeof``-derived constant limits (array objects and string literals)
- concrete index maxima retained across ``i++`` so post-loop writes after
  ``for (i = 0; i < N; i++)`` stay proven when ``N < capacity``
- ``can_access_at_index``-style cursor guards
  ``(buf->offset + i) < buf->length`` for ``(buf->content + buf->offset)[i]``
- symbolic maxima on other scalars (e.g. ``length <= sizeof(buf) - 1``)
"""

from collections import deque
import re
from typing import Callable, Dict, FrozenSet, Optional, Tuple, Union

from pycparser import c_ast

from ...cfg.affine_relations import AffineFacts, join_affine, transfer_affine


Capacity = Optional[Union[int, str]]
SizeofEnv = Dict[str, int]
VarMax = FrozenSet[Tuple[str, int]]
# lower, upper, affine, index_max, var_max, cursor_bases
BoundFacts = Tuple[bool, bool, AffineFacts, Optional[int], VarMax, FrozenSet[str]]


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


def _string_sizeof(value: str) -> Optional[int]:
    """Byte size of a C string literal including the NUL terminator."""
    if len(value) < 2 or value[0] not in "\"'" or value[-1] != value[0]:
        return None
    try:
        # Strip surrounding quotes and interpret simple escapes.
        body = value[1:-1]
        # bytes.decode unicode-escape handles \\ \" \\n etc. for our fixtures.
        decoded = body.encode("utf-8").decode("unicode_escape")
        return len(decoded.encode("latin-1")) + 1
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
        # Conservative fallback: raw length between quotes + NUL, counting \\x as one.
        return len(value) - 1  # quotes removed roughly; include NUL via -2+1


def _integer(node, sizeof_env: Optional[SizeofEnv] = None):
    if isinstance(node, c_ast.Constant) and node.type == "int":
        token = re.sub(r"[uUlL]+$", "", node.value)
        try:
            return int(token, 8 if len(token) > 1 and token.startswith("0") and token.isdigit() else 0)
        except ValueError:
            return None
    if isinstance(node, c_ast.Constant) and node.type == "string" and isinstance(node.value, str):
        # Only meaningful under sizeof(); callers use UnaryOp sizeof.
        return None
    if isinstance(node, c_ast.Cast):
        return _integer(node.expr, sizeof_env)
    if isinstance(node, c_ast.UnaryOp) and node.op in {"+", "-"}:
        value = _integer(node.expr, sizeof_env)
        return None if value is None else value if node.op == "+" else -value
    if isinstance(node, c_ast.UnaryOp) and node.op == "sizeof":
        expr = node.expr
        if isinstance(expr, c_ast.Constant) and expr.type == "string" and isinstance(expr.value, str):
            return _string_sizeof(expr.value)
        if isinstance(expr, c_ast.ID) and sizeof_env and expr.name in sizeof_env:
            return sizeof_env[expr.name]
        return None
    if isinstance(node, c_ast.BinaryOp) and node.op in {"+", "-", "*"}:
        left, right = _integer(node.left, sizeof_env), _integer(node.right, sizeof_env)
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


def _var_max_get(var_max: VarMax, name: str) -> Optional[int]:
    for key, value in var_max:
        if key == name:
            return value
    return None


def _var_max_set(var_max: VarMax, name: str, value: int) -> VarMax:
    return frozenset((key, val) for key, val in var_max if key != name) | {(name, value)}


def _var_max_clear(var_max: VarMax, names) -> VarMax:
    names = set(names)
    return frozenset((key, val) for key, val in var_max if key not in names)


def _var_max_join(left: VarMax, right: VarMax) -> VarMax:
    """Keep a name only when both sides agree on the same maximum."""
    right_map = dict(right)
    return frozenset(
        (name, value)
        for name, value in left
        if right_map.get(name) == value
    )


def _struct_base_field(node) -> Optional[Tuple[str, str]]:
    """Return (base, field) for ``base->field`` / ``base.field``."""
    if isinstance(node, c_ast.StructRef) and isinstance(node.name, c_ast.ID) and isinstance(node.field, c_ast.ID):
        return node.name.name, node.field.name
    return None


def _cursor_guard_base(expr, index: str) -> Optional[str]:
    """Match ``(buf->offset + index) < buf->length`` (either addend order)."""
    if not isinstance(expr, c_ast.BinaryOp) or expr.op != "<":
        return None
    left, right = expr.left, expr.right
    limit = _struct_base_field(right)
    if limit is None or limit[1] != "length":
        return None
    if not isinstance(left, c_ast.BinaryOp) or left.op != "+":
        return None

    def offset_base(side):
        field = _struct_base_field(side)
        return field[0] if field and field[1] == "offset" else None

    if isinstance(left.left, c_ast.ID) and left.left.name == index:
        base = offset_base(left.right)
    elif isinstance(left.right, c_ast.ID) and left.right.name == index:
        base = offset_base(left.left)
    else:
        return None
    return base if base == limit[0] else None


def _is_cursor_access(access, index: str, base: str) -> bool:
    """Match ``(buf->content + buf->offset)[index]``."""
    if not isinstance(access.subscript, c_ast.ID) or access.subscript.name != index:
        return False
    name = access.name
    if not isinstance(name, c_ast.BinaryOp) or name.op != "+":
        return False

    def field(side, expected):
        info = _struct_base_field(side)
        return info is not None and info[0] == base and info[1] == expected

    return (
        (field(name.left, "content") and field(name.right, "offset"))
        or (field(name.left, "offset") and field(name.right, "content"))
    )


def _unwrap_cast(node):
    while isinstance(node, c_ast.Cast):
        node = node.expr
    return node


def guarded_access(
    cfg,
    target_id,
    access,
    index,
    capacity: Capacity,
    signed,
    sizeof_env: Optional[SizeofEnv] = None,
):
    """Prove both bounds at this exact access on every reachable CFG path.

    ``capacity`` is either a concrete element count or the name of a scalar
    whose value is explicitly contracted to be the indexed object's element
    capacity. Unknown pointer extents are represented by ``None`` and do not
    make arbitrary symbolic comparisons into bounds proofs, except for
    recognized cursor-buffer access macros.

    ``sizeof_env`` maps local array names to their ``sizeof`` byte sizes so
    ``i < sizeof(buf) - 1`` can be evaluated as a constant limit.

    The relational component records must-hold facts such as ``i == y + C``.
    They are joined by intersection at CFG merge points, so path-dependent or
    divergent loop updates cannot accidentally suppress a finding.
    """
    if cfg.entry is None or target_id is None:
        return False

    sizeof_env = sizeof_env or {}
    capacity_symbol = capacity if isinstance(capacity, str) else None
    # Cursor accesses are proven via can_access-style guards, not a plain ID
    # subscript requirement alone — still require the index ID in the subscript
    # for non-cursor cases.
    cursor_access_bases = []
    if isinstance(access.subscript, c_ast.ID) and access.subscript.name == index:
        # Discover whether this access itself is a cursor form for any base.
        name = access.name
        if isinstance(name, c_ast.BinaryOp) and name.op == "+":
            left_f, right_f = _struct_base_field(name.left), _struct_base_field(name.right)
            if left_f and right_f and left_f[0] == right_f[0]:
                fields = {left_f[1], right_f[1]}
                if fields == {"content", "offset"}:
                    cursor_access_bases.append(left_f[0])
    elif not isinstance(access.subscript, c_ast.ID) or access.subscript.name != index:
        # A bound on A alone does not prove A + offset or a cast is in range.
        return False

    empty_var_max: VarMax = frozenset()
    # Unsigned indexes start with a lower bound only. A concrete maximum is
    # established solely by comparisons or constant assignments — never by
    # assuming the parameter equals zero.
    initial: BoundFacts = (not signed, False, AffineFacts(), None, empty_var_max, frozenset())

    def join(a: BoundFacts, b: BoundFacts) -> BoundFacts:
        # Index maxima must agree exactly. Taking max() would climb forever
        # around ``i++`` loops and never reach a fixed point.
        a_max, b_max = a[3], b[3]
        joined_max = a_max if a_max is not None and a_max == b_max else None
        return (
            a[0] and b[0],
            a[1] and b[1],
            join_affine(a[2], b[2]),
            joined_max,
            _var_max_join(a[4], b[4]),
            a[5] & b[5],
        )

    def reset_bounds(facts: BoundFacts, *, clear_relations=False, clear_index_max=True) -> BoundFacts:
        return (
            not signed,
            False,
            AffineFacts() if clear_relations else facts[2],
            None if clear_index_max else facts[3],
            empty_var_max if clear_relations else facts[4],
            frozenset() if clear_relations else facts[5],
        )

    def apply_index_max(facts: BoundFacts, new_max: Optional[int]) -> BoundFacts:
        if new_max is None:
            return facts
        current = facts[3]
        merged = new_max if current is None else min(current, new_max)
        return (facts[0], facts[1], facts[2], merged, facts[4], facts[5])

    def upper_from_index_max(facts: BoundFacts) -> bool:
        if not isinstance(capacity, int) or facts[3] is None:
            return False
        return facts[3] < capacity

    def upper_from_symbol_limit(limit_name: str, facts: BoundFacts, *, strict: bool) -> bool:
        """``i < limit`` (strict) or ``i <= limit`` with a known max on limit."""
        limit_max = _var_max_get(facts[4], limit_name)
        if limit_max is None:
            return False
        if isinstance(capacity, int):
            # i < limit <= M  => i <= M-1; need M-1 < capacity <=> M <= capacity
            # i <= limit <= M => i <= M; need M < capacity
            return (limit_max <= capacity) if strict else (limit_max < capacity)
        if capacity_symbol is not None and limit_name == capacity_symbol and strict:
            return True
        return False

    def refine(expr, truth, facts: BoundFacts) -> BoundFacts:
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

        cursor_base = _cursor_guard_base(expr, index) if truth else None
        if cursor_base is not None:
            lower, upper, affine, index_max, var_max, cursors = facts
            if not signed:
                lower = True
            if cursor_base in cursor_access_bases or capacity is None:
                # Cursor guard proves the content[offset+i] access; also
                # strengthens a fixed-array proof when capacity is known.
                upper = True if cursor_base in cursor_access_bases else upper
            return lower, upper, affine, index_max, var_max, cursors | {cursor_base}

        if not isinstance(expr, c_ast.BinaryOp):
            return facts

        left, right, op = expr.left, expr.right, expr.op
        if not truth:
            op = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}.get(op, "")

        affine = facts[2]
        candidate = None
        offset = 0
        # Track maxima for arbitrary IDs (length checks), not only the index.
        plain_left = _unwrap_cast(left)
        plain_right = _unwrap_cast(right)

        if isinstance(plain_left, c_ast.ID):
            relation = affine.offset(index, plain_left.name)
            if relation is not None:
                candidate, offset = plain_left.name, relation
            elif plain_left.name == index:
                candidate, offset = index, 0
        if candidate is None and isinstance(plain_right, c_ast.ID):
            relation = affine.offset(index, plain_right.name)
            if relation is not None:
                left, right = right, left
                plain_left, plain_right = plain_right, plain_left
                op = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}.get(op, op)
                candidate, offset = plain_left.name, relation
            elif plain_right.name == index:
                left, right = right, left
                plain_left, plain_right = plain_right, plain_left
                op = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}.get(op, op)
                candidate, offset = index, 0

        lower, upper, _, index_max, var_max, cursors = facts
        limit = _integer(right, sizeof_env)

        # Record concrete maxima for the compared scalar (e.g. length <= 25).
        if isinstance(plain_left, c_ast.ID) and limit is not None:
            name = plain_left.name
            if op == "<":
                var_max = _var_max_set(var_max, name, limit - 1 + offset if name == index else limit - 1)
            elif op == "<=":
                var_max = _var_max_set(var_max, name, limit + offset if name == index else limit)
            elif op == "==":
                var_max = _var_max_set(var_max, name, limit)

        if candidate is None:
            return lower, upper, affine, index_max, var_max, cursors

        if limit is None:
            # Symbolic upper: i < length / i < capacity_symbol
            limit_node = _unwrap_cast(right)
            if isinstance(limit_node, c_ast.ID) and op == "<" and offset <= 0:
                if capacity_symbol is not None and limit_node.name == capacity_symbol:
                    upper = True
                elif upper_from_symbol_limit(limit_node.name, (lower, upper, affine, index_max, var_max, cursors), strict=True):
                    upper = True
                    # Also tighten index_max from the known limit maximum.
                    limit_max = _var_max_get(var_max, limit_node.name)
                    if limit_max is not None:
                        index_max = limit_max - 1 if index_max is None else min(index_max, limit_max - 1)
            return lower, upper, affine, index_max, var_max, cursors

        if not signed and limit < 0:
            # Usual arithmetic conversions can turn a negative limit into
            # a large unsigned value; do not interpret it as a small bound.
            return lower, upper, affine, index_max, var_max, cursors

        translated = limit + offset
        if op in {">=", ">", "=="}:
            lower |= translated + (op == ">") >= 0
        if op in {"<", "<=", "=="}:
            # For i == y + C, y < L proves i < capacity exactly when
            # L + C <= capacity (and similarly for <= / ==).
            upper |= isinstance(capacity, int) and translated + (op != "<") <= capacity
            # Retain a concrete max so loop-exit edges still prove the write.
            if op == "<":
                new_max = translated - 1
            else:
                new_max = translated
            index_max = new_max if index_max is None else min(index_max, new_max)
            upper |= upper_from_index_max((lower, upper, affine, index_max, var_max, cursors))
        return lower, upper, affine, index_max, var_max, cursors

    def at_access(expr, facts: BoundFacts):
        if expr is None:
            return None
        if expr is access:
            # Side effects within a subscript are not covered by an ID proof.
            if _effects(expr.subscript, index):
                return reset_bounds(facts, clear_relations=True)
            lower, upper, affine, index_max, var_max, cursors = facts
            upper = upper or upper_from_index_max(facts)
            if cursors and any(_is_cursor_access(access, index, base) for base in cursors):
                upper = True
                if not signed:
                    lower = True
            return lower, upper, affine, index_max, var_max, cursors
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

    def transfer_index_max(ast_node, writes, facts: BoundFacts) -> BoundFacts:
        """Update concrete maxima for unit increments and constant assigns."""
        lower, upper, affine, index_max, var_max, cursors = facts
        if index in writes:
            upper = False
            cursors = frozenset()
        var_max = _var_max_clear(var_max, writes)

        node = ast_node
        if isinstance(node, c_ast.UnaryOp) and node.op in {"++", "p++"} and isinstance(node.expr, c_ast.ID):
            if node.expr.name == index:
                index_max = None if index_max is None else index_max + 1
            name = node.expr.name
            prior = _var_max_get(facts[4], name)
            if prior is not None:
                var_max = _var_max_set(var_max, name, prior + 1)
        elif isinstance(node, c_ast.UnaryOp) and node.op in {"--", "p--"} and isinstance(node.expr, c_ast.ID):
            if node.expr.name == index:
                index_max = None if index_max is None else index_max - 1
        elif isinstance(node, c_ast.Assignment) and isinstance(node.lvalue, c_ast.ID):
            name = node.lvalue.name
            if node.op == "=":
                value = _integer(node.rvalue, sizeof_env)
                if name == index:
                    index_max = value
                if value is not None:
                    var_max = _var_max_set(var_max, name, value)
                elif name == index:
                    index_max = None
                else:
                    var_max = _var_max_clear(var_max, {name})
            elif node.op == "+=" and name == index:
                step = _integer(node.rvalue, sizeof_env)
                index_max = None if index_max is None or step is None else index_max + step
            elif name == index:
                index_max = None
        elif index in writes:
            index_max = None

        # After i++ the boolean capacity proof no longer holds, but index_max
        # may still prove the next access (including the loop-exit write).
        upper = upper or upper_from_index_max((lower, upper, affine, index_max, var_max, cursors))
        return lower, upper, affine, index_max, var_max, cursors

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
            if proof is None:
                return False
            lower_ok, upper_ok = proof[0], proof[1]
            if not upper_ok:
                upper_ok = upper_from_index_max(proof)
            if cursors := proof[5]:
                if any(_is_cursor_access(access, index, base) for base in cursors):
                    upper_ok = True
                    if not signed:
                        lower_ok = True
            if not (lower_ok and upper_ok):
                return False
            # Continue through the target to verify later loop iterations.

        if event.kind.endswith("_cond"):
            for successor in event.successors:
                edge_truth = cfg.edge_truth.get((node_id, successor))
                out = refine(expr, edge_truth, facts) if edge_truth is not None else join(
                    refine(expr, True, facts), refine(expr, False, facts)
                )
                # Loop-exit edges: false on ``i < N`` keeps index_max from the
                # increment path (typically N), which still proves i < capacity
                # when N < capacity.
                if not out[1]:
                    lower, upper, affine, index_max, var_max, cursors = out
                    upper = upper or upper_from_index_max(out)
                    out = (lower, upper, affine, index_max, var_max, cursors)
                queue.append((successor, out))
            continue

        affine = transfer_affine(
            getattr(event, "_ast_node", None),
            getattr(event, "writes", set()),
            facts[2],
            has_unknown_call=bool(getattr(event, "calls", ())) or _contains_call(expr),
        )
        base = (facts[0], facts[1], affine, facts[3], facts[4], facts[5])
        if index in event.writes or _effects(expr, index):
            # Preserve/update concrete maxima across unit increments.
            out = transfer_index_max(getattr(event, "_ast_node", None), event.writes, base)
            out = (not signed, out[1], out[2], out[3], out[4], frozenset())
            # Re-apply unsigned lower and capacity proof from index_max.
            lower, upper, aff, index_max, var_max, cursors = out
            lower = not signed
            upper = upper_from_index_max(out)
            out = (lower, upper, aff, index_max, var_max, cursors)
        elif _writes_symbol(event, capacity_symbol):
            # Reassigning the contracted length invalidates the upper proof.
            out = transfer_index_max(getattr(event, "_ast_node", None), event.writes, base)
            out = (out[0], False, out[2], out[3], out[4], out[5])
        else:
            out = transfer_index_max(getattr(event, "_ast_node", None), event.writes, base)
        queue.extend((successor, out) for successor in event.successors)
    return reached
