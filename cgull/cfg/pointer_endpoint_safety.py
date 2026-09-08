"""Non-wrapping endpoint evidence, kept separate from the bounds being tested."""
from pycparser import c_ast
from pycparser.c_generator import CGenerator
from .integer_ranges import IntegerRange


_GENERATOR = CGenerator()


def key(node):
    return _GENERATOR.visit(node)


def address(node, state):
    from .pointer_ranges import _expression_type, _unwrap_type
    typ = _unwrap_type(_expression_type(node, state))
    if isinstance(typ, (c_ast.PtrDecl, c_ast.ArrayDecl)):
        return True
    if isinstance(node, c_ast.Cast):
        # Only explicit, unsigned address-sized conversions preserve identity.
        names = getattr(typ, 'names', ())
        return 'unsigned' in names and 'long' in names and address(node.expr, state)
    if isinstance(node, c_ast.BinaryOp) and node.op in {'+', '-'}:
        left, right = address(node.left, state), address(node.right, state)
        return (left and not right) or (node.op == '+' and right and not left)
    if isinstance(node, c_ast.ID):
        return node.name in state.address_values or node.name in state.address_names
    return False


def interval(node, state):
    from .pointer_ranges import _constant_size, _unwrap_type
    from .pointer_guards import _volatile_type
    if isinstance(node, c_ast.ID) and _volatile_type(state.types.get(node.name)):
        return IntegerRange()
    value = _constant_size(node, state)
    if value is not None:
        return IntegerRange(value, value)
    if isinstance(node, c_ast.ID):
        if node.name in state.integer_bounds:
            return state.integer_bounds[node.name]
        names = getattr(_unwrap_type(state.types.get(node.name)), 'names', ())
        if 'unsigned' in names:
            return IntegerRange(0, None)
    return IntegerRange()


def ordered(a, b, state):
    if volatile(a, state) or volatile(b, state):
        return False
    return key(a) == key(b) or (key(a), key(b)) in state.address_order


def endpoint_safe(node, state):
    from .pointer_ranges import _expression_fact
    a, b = node.left, node.right
    if node.op == '+' and not address(a, state):
        a, b = b, a
    if not address(a, state):
        return True
    if volatile(a, state) or volatile(b, state):
        return False
    if address(b, state):
        return node.op == '-' and (ordered(b, a, state) or pointers(a, b, state))
    size = interval(b, state)
    if size.lower is None or size.lower < 0:
        return False
    if size.upper == 0:
        return True
    from .pointer_ranges import _expression_type, _unwrap_type, _type_width
    typ = _unwrap_type(_expression_type(a, state))
    names = getattr(typ, 'names', ())
    numeric = interval(a, state)
    if 'unsigned' in names and numeric.lower is not None and numeric.upper is not None and size.upper is not None:
        width = _type_width(typ)
        if node.op == '-' and numeric.lower >= size.upper:
            return True
        if node.op == '+' and width and numeric.upper + size.upper < (1 << (8 * width)):
            return True
    fact = _expression_fact(a, state)
    capacity = fact.forward_accessible_extent if node.op == '+' else fact.backward_accessible_extent
    if size.upper is not None and capacity is not None and fact.element_width:
        if size.upper * fact.element_width <= capacity:
            return True
    if size.upper is not None and fact.offset.is_exact and fact.element_width:
        amount = size.upper * fact.element_width
        start = fact.offset.lower - (amount if node.op == '-' else 0)
        end = fact.offset.lower + (amount if node.op == '+' else 0)
        if any(lo <= start and end <= hi for lo, hi in fact.proven_intervals):
            return True
    # A prior distance check constrains this exact expression; it must have
    # been evaluated only after the endpoint order was established.
    return (key(a), key(b), node.op) in state.safe_endpoints


def unsafe_endpoints(node, state):
    result = []
    def walk(n):
        if n is None or isinstance(n, c_ast.FuncCall):
            return
        if isinstance(n, c_ast.Cast) and isinstance(n.expr, c_ast.BinaryOp) and n.expr.op == '-':
            from .pointer_ranges import _expression_type, _unwrap_type
            names = getattr(_unwrap_type(_expression_type(n, state)), 'names', ())
            if 'unsigned' in names and address(n.expr.left, state) and address(n.expr.right, state) and not ordered(n.expr.right, n.expr.left, state):
                result.append(n.expr)
        if isinstance(n, c_ast.ID) and n.name in state.address_values:
            result.extend(state.address_values[n.name])
        if isinstance(n, c_ast.BinaryOp) and n.op in {'+', '-'}:
            if (address(n.left, state) or (n.op == '+' and address(n.right, state))) and not endpoint_safe(n, state):
                result.append(n)
        for _, child in n.children():
            walk(child)
    walk(node)
    return result


def refine_safety(node, state, truth):
    if not isinstance(node, c_ast.BinaryOp) or node.op not in {'<', '<=', '>', '>='}:
        return
    a, b, op = node.left, node.right, node.op
    if not truth:
        op = {'<': '>=', '<=': '>', '>': '<=', '>=': '<'}[op]
    if op in {'>', '>='}:
        a, b = b, a
        op = '<' if op == '>' else '<='
    if address(a, state) and address(b, state):
        state.address_order.add((key(a), key(b)))
    # Nonnegative symbolic sizes can be bounded by a prior constant guard.
    if isinstance(a, c_ast.ID) and compatible_numeric_guard(a, b, state):
        bound = interval(b, state)
        old = interval(a, state)
        if bound.upper is not None:
            state.integer_bounds[a.name] = old.intersect(IntegerRange(None, bound.upper - (op == '<'))) or old
    if isinstance(b, c_ast.ID) and compatible_numeric_guard(b, a, state):
        bound = interval(a, state)
        old = interval(b, state)
        if bound.lower is not None:
            state.integer_bounds[b.name] = old.intersect(IntegerRange(bound.lower + (op == '<'), None)) or old
    from .pointer_ranges import _expression_type, _unwrap_type
    if isinstance(b, c_ast.Cast):
        names = getattr(_unwrap_type(_expression_type(b, state)), 'names', ())
        if 'unsigned' not in names:
            return  # A signed narrowing cast can become negative before promotion.
    distance = b.expr if isinstance(b, c_ast.Cast) else b
    if isinstance(distance, c_ast.BinaryOp) and distance.op == '-' and address(distance.left, state) and address(distance.right, state):
        if ordered(distance.right, distance.left, state) and interval(a, state).lower is not None and interval(a, state).lower >= 0:
            state.safe_endpoints.add((key(distance.right), key(a), '+'))
            state.safe_endpoints.add((key(distance.left), key(a), '-'))


def observe_checks(node, state, registry):
    """Honor short circuit evaluation when diagnosing a range comparison."""
    from .pointer_ranges import _validate_condition
    result = []
    def walk(n, current):
        if n is None:
            return
        if isinstance(n, c_ast.BinaryOp) and n.op in {'&&', '||'}:
            walk(n.left, current)
            edge = current.copy()
            _validate_condition(n.left, edge, registry, n.op == '&&')
            walk(n.right, edge)
            return
        if isinstance(n, c_ast.BinaryOp) and n.op in {'<', '<=', '>', '>='}:
            result.extend((n, expr) for expr in unsafe_endpoints(n, current))
            return
        if isinstance(n, c_ast.UnaryOp) and n.op == 'sizeof':
            return
        for _, child in n.children():
            walk(child, current)
    walk(node, state)
    return result


def pointers(a, b, state):
    # Signed ptrdiff_t comparisons preserve negative distances. As in the
    # enclosing-range domain, compatible pointers are assumed in one array.
    from .pointer_ranges import _expression_type, _unwrap_type
    types = [_unwrap_type(_expression_type(n, state)) for n in (a, b)]
    return all(isinstance(t, (c_ast.PtrDecl, c_ast.ArrayDecl)) for t in types) and key(types[0].type) == key(types[1].type)


def depends_on(proof, name):
    import re
    return any(name in re.findall(r"[A-Za-z_][A-Za-z_0-9]*", term) for term in proof)


def volatile(node, state):
    from .pointer_guards import _dependencies, _volatile_type
    return any(_volatile_type(state.types.get(name)) for name in _dependencies(node))


def compatible_numeric_guard(target, bound, state):
    from .pointer_ranges import _expression_type, _unwrap_type
    def unsigned(n):
        names = getattr(_unwrap_type(_expression_type(n, state)), 'names', ())
        return 'unsigned' in names or isinstance(n, c_ast.Constant) and 'unsigned' in n.type
    if volatile(target, state) or volatile(bound, state):
        return False
    # Unsigned conversion can make a negative signed value satisfy >= 0u.
    return unsigned(target) or not unsigned(bound)
