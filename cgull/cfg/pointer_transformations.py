"""Transformations of the shared range fact; no independent provenance state."""

from dataclasses import replace

from pycparser import c_ast, c_generator

_GENERATOR = c_generator.CGenerator()

from . import pointer_ranges as ranges


def lost_fact(fact):
    if fact.origin is None and not fact.degradations.intersection({'PROVENANCE_LOST', 'UNPROVEN_CONTAINER'}):
        return ranges.PointerRangeFact()
    # Keep only the symbolic dependency for interprocedural requirements.
    # It is not evidence of object identity after a lossy transformation.
    return replace(fact.unknown_offset('PROVENANCE_LOST'),
                   object_extent=None, containing_type=None, validated_intervals=(), guarded_intervals=(),
                   provenance=ranges.PointerProvenance.UNKNOWN)


def address_integer(typ):
    typ = ranges._unwrap_type(typ)
    names = getattr(typ, 'names', ())
    return isinstance(typ, c_ast.IdentifierType) and 'unsigned' in names and 'long' in names


def integer_fact(node, typ, state):
    fact = ranges._expression_fact(node, state)
    if address_integer(typ) and not ranges._volatile_type(typ):
        return replace(fact, element_width=1)
    return lost_fact(fact)


def pointer_expression(node, state):
    typ = ranges._unwrap_type(ranges._expression_type(node, state))
    if isinstance(typ, (c_ast.PtrDecl, c_ast.ArrayDecl)):
        return True
    if isinstance(node, c_ast.UnaryOp) and node.op == '&':
        return True
    if isinstance(node, c_ast.BinaryOp) and node.op in {'+', '-'}:
        left, right = pointer_expression(node.left, state), pointer_expression(node.right, state)
        return left != right and (node.op == '+' or left)
    return False


def cast_fact(node, state, width):
    typ = ranges._resolve_type(node.to_type.type, state.typedefs)
    if not isinstance(ranges._unwrap_type(typ), c_ast.PtrDecl):
        return integer_fact(node.expr, typ, state)
    fact = ranges._expression_fact(node.expr, state)
    expression = node.expr
    while isinstance(expression, c_ast.Cast):
        expression = expression.expr
    if isinstance(expression, c_ast.BinaryOp) and expression.op == '-' and offsetof_value(expression.right, state) is not None:
        # Numeric range validation alone cannot prove an enclosing object.
        recovery_type = _GENERATOR.visit(ranges._unwrap_type(ranges._unwrap_type(typ).type))
        if fact.containing_type != recovery_type or fact.offset.exact_value != 0:
            fact = replace(fact, degradations=fact.degradations | {'UNPROVEN_CONTAINER'},
                           lower_bound=None, upper_bound=None, validated_intervals=(), guarded_intervals=(), recovery_type=recovery_type)
    target = ranges._unwrap_type(typ).type
    alignment = ranges._type_alignment(target)
    origin_alignment = ranges._type_alignment(state.types.get(fact.origin))
    if fact.object_extent is not None and alignment and origin_alignment and origin_alignment >= alignment and fact.offset.is_exact and fact.offset.lower % alignment and not fact.definitely_outside(width or 0):
        fact = lost_fact(fact)
    return replace(fact, element_width=width)


def object_address(node, state):
    if isinstance(node, c_ast.ID):
        typ = state.types.get(node.name)
        width = ranges._type_width(typ)
        if width is not None:
            return ranges.PointerRangeFact.object(node.name, width, element_width=width)
    if isinstance(node, c_ast.StructRef):
        if node.type == '->':
            fact, width = ranges._member_access(node, state)
        else:
            fact = object_address(node.name, state)
            typ = ranges._unwrap_type(ranges._expression_type(node.name, state))
            layout = ranges._aggregate_layout(typ)
            if layout is None or node.field.name not in layout[2]:
                return fact.unknown_offset('UNKNOWN_MEMBER_LAYOUT')
            offset, width = layout[2][node.field.name]
            fact = fact.shifted(offset)
        parent_type = ranges._unwrap_type(ranges._expression_type(node.name, state))
        if isinstance(parent_type, c_ast.PtrDecl):
            parent_type = ranges._unwrap_type(parent_type.type)
        return replace(fact, element_width=width, containing_type=_GENERATOR.visit(parent_type) if parent_type is not None and fact.object_extent is not None else None)
    return ranges.PointerRangeFact()


def offsetof_layout(node, state):
    """Recognize the conventional expanded offsetof: (size_t)&((T *)0)->m."""
    while isinstance(node, c_ast.Cast):
        node = node.expr
    if not isinstance(node, c_ast.UnaryOp) or node.op != '&':
        return None
    member = node.expr
    if not isinstance(member, c_ast.StructRef) or member.type != '->':
        return None
    base = member.name
    if not isinstance(base, c_ast.Cast) or ranges._constant_int(base.expr) != 0:
        return None
    typ = ranges._unwrap_type(ranges._resolve_type(base.to_type.type, state.typedefs))
    if not isinstance(typ, c_ast.PtrDecl):
        return None
    layout = ranges._aggregate_layout(ranges._unwrap_type(typ.type))
    aggregate = ranges._unwrap_type(typ.type)
    offset = layout[2][member.field.name][0] if layout and member.field.name in layout[2] else None
    return _GENERATOR.visit(aggregate), offset


def subtraction_fact(node, state):
    if node.op != '-' or not (pointer_expression(node.left, state) and pointer_expression(node.right, state)):
        return None
    left = ranges._expression_fact(node.left, state)
    right = ranges._expression_fact(node.right, state)
    concrete = {ranges.PointerProvenance.LOCAL_OBJECT, ranges.PointerProvenance.ALLOCATION}
    if left.origin and right.origin and left.origin != right.origin and left.provenance in concrete and right.provenance in concrete:
        return ranges.PointerRangeFact(degradations=frozenset({'CROSS_OBJECT_SUBTRACTION'}))
    # Distinct formals can alias; unknown origin is not proof of a violation.
    return ranges.PointerRangeFact()


def offset_fact(base, count, is_pointer):
    shifted = base.shifted_elements(count)
    if is_pointer or count == 0:
        return shifted
    # Address integers can wrap; retain only arithmetic within a known object.
    if base.object_extent is not None and shifted.offset.is_exact and 0 <= shifted.offset.lower <= base.object_extent:
        return shifted
    return lost_fact(base)


def member_type(node, state):
    typ = ranges._unwrap_type(ranges._expression_type(node.name, state))
    if node.type == '->' and isinstance(typ, c_ast.PtrDecl):
        typ = ranges._unwrap_type(typ.type)
    return next((m.type for m in (getattr(typ, 'decls', ()) or ()) if m.name == node.field.name), None)


def offsetof_value(node, state):
    layout = offsetof_layout(node, state)
    return layout[1] if layout else None


def recover_fact(fact, node, state):
    layout = offsetof_layout(node, state)
    if layout is None:
        return fact
    target, offset = layout
    if fact.containing_type == target and offset is not None and fact.offset.exact_value == 0:
        return fact
    return replace(fact, degradations=fact.degradations | {'UNPROVEN_CONTAINER'},
                   lower_bound=None, upper_bound=None, validated_intervals=(), guarded_intervals=(),
                   recovery_type=target)
