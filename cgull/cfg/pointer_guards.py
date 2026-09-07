"""Relational edge refinements for the shared pointer-range domain.

C relational pointer comparisons are interpreted within an enclosing array,
not as an address-validity or allocation-liveness test. Only compatible pointer
terms and nonnegative, representable constant distances are accepted.
"""

from dataclasses import dataclass, replace

from pycparser import c_ast


@dataclass(frozen=True)
class GuardedInterval:
    lower: int
    upper: int
    dependencies: frozenset[str]


def join_guarded_intervals(left, right):
    result = set()
    for a in left:
        for b in right:
            lower, upper = max(a.lower, b.lower), min(a.upper, b.upper)
            if lower <= upper:
                result.add(GuardedInterval(lower, upper, a.dependencies | b.dependencies))
    return tuple(sorted(result, key=lambda p: (p.lower, p.upper, sorted(p.dependencies))))


def invalidate_pointer_guards(state, target):
    for name, fact in list(state.facts.items()):
        intervals = tuple(p for p in fact.guarded_intervals if target not in p.dependencies)
        if intervals != fact.guarded_intervals:
            state.facts[name] = replace(fact, guarded_intervals=intervals)
    state.constants.pop(target, None)


def _dependencies(node):
    if isinstance(node, c_ast.ID):
        return frozenset({node.name})
    if isinstance(node, c_ast.UnaryOp) and node.op == 'sizeof':
        return frozenset()
    return frozenset().union(*(_dependencies(child) for _, child in node.children()))


def _volatile_type(typ):
    while typ is not None:
        if "volatile" in (getattr(typ, "quals", ()) or ()):
            return True
        typ = getattr(typ, "type", None)
    return False


def _pointer_term(node, state):
    from .pointer_ranges import _constant_size, _unwrap_type

    if isinstance(node, c_ast.ID):
        if _volatile_type(state.types.get(node.name)):
            return None
        typ = _unwrap_type(state.types.get(node.name))
        if isinstance(typ, (c_ast.PtrDecl, c_ast.ArrayDecl)):
            # Structural type identity, including signedness, not just width.
            from pycparser.c_generator import CGenerator
            signature = CGenerator().visit(typ.type)
            fact = state.facts.get(node.name)
            if fact and fact.element_width and fact.offset.is_exact:
                return node.name, 0, fact.element_width, signature
        return None
    if isinstance(node, c_ast.BinaryOp) and node.op in {'+', '-'}:
        term = _pointer_term(node.left, state)
        size = _constant_size(node.right, state)
        if node.op == '+' and term is None:
            term = _pointer_term(node.right, state)
            size = _constant_size(node.left, state)
        # Nested arithmetic is deliberately excluded: its intermediate overflow
        # and pointer-formation requirements are not proved here.
        if term and term[1] == 0 and size is not None and 0 <= size <= (1 << 31) - 1:
            return term[0], (size if node.op == '+' else -size) * term[2], term[2], term[3]
    return None


def _signed_distance(node, state):
    from .pointer_ranges import _constant_size, _unwrap_type

    value = _constant_size(node, state)
    if value is None or not 0 <= value <= (1 << 31) - 1:
        return None
    # ptrdiff_t compared with size_t/unsigned can turn a negative distance into
    # a large positive value. Exclude such forms rather than assume an ABI.
    while isinstance(node, c_ast.UnaryOp) and node.op in {'+', '-'}:
        node = node.expr
    typ = _unwrap_type(state.types.get(node.name)) if isinstance(node, c_ast.ID) else None
    names = getattr(typ, 'names', ())
    if 'unsigned' in names or (isinstance(node, c_ast.Constant) and 'unsigned' in node.type):
        return None
    if isinstance(node, c_ast.UnaryOp) and node.op == 'sizeof':
        return None
    return value


def refine_pointer_comparison(node, state, truth):
    """Refine one relational leaf on its guaranteed true/false edge."""
    if not isinstance(node, c_ast.BinaryOp) or node.op not in {'<', '<=', '>', '>='}:
        return
    op, left, right = node.op, node.left, node.right
    if not truth:
        op = {'<': '>=', '<=': '>', '>': '<=', '>=': '<'}[op]
    # Normalize both direct and subtraction forms to A >= B + distance.
    distance = 0
    a, b = _pointer_term(left, state), _pointer_term(right, state)
    if a is None or b is None:
        if isinstance(right, c_ast.BinaryOp) and right.op == '-':
            left, right = right, left
            op = {'<': '>', '<=': '>=', '>': '<', '>=': '<='}[op]
        if not isinstance(left, c_ast.BinaryOp) or left.op != '-':
            return
        a, b = _pointer_term(left.left, state), _pointer_term(left.right, state)
        distance = _signed_distance(right, state)
        if a is None or b is None or distance is None or op not in {'>', '>='}:
            return
        distance *= a[2]
    elif op in {'<', '<='}:
        a, b = b, a
        op = '>' if op == '<' else '>='
    if a[2:] != b[2:] or a[0] == b[0]:
        return
    distance += b[1] - a[1] + (a[2] if op == '>' else 0)
    if not 0 <= distance <= (1 << 31) - 1:
        return
    dependencies = _dependencies(node)
    # A has `distance` bytes behind it; B has that many bytes ahead.
    for name, lower, upper in ((a[0], -distance, 0), (b[0], 0, distance)):
        anchor = state.facts[name]
        for key, fact in list(state.facts.items()):
            if fact.origin is not None and fact.origin == anchor.origin:
                proof = GuardedInterval(anchor.offset.lower + lower, anchor.offset.lower + upper, dependencies)
                intervals = set(fact.guarded_intervals) | {proof}
                state.facts[key] = replace(fact, guarded_intervals=tuple(sorted(
                    intervals, key=lambda p: (p.lower, p.upper, sorted(p.dependencies)))))
