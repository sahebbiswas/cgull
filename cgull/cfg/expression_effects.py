"""Ordered scalar and subobject effects for CFG expression construction.

The CFG stores scalar read/write facts as sets, but some C expressions need an
ordered walk to derive those facts correctly. In particular, compound
assignments and mutating unary operators both read and write their scalar
target, while lvalue address/index expressions can have their own reads and
mutations. Keeping the ordered derivation here gives every CFG consumer one
authoritative semantic boundary without pretending indirect stores are writes
to the pointer/array variable used to address them.

``ordered_storage_effects`` exposes a parallel, more precise stream for
consumers that need direct aggregate-subobject identity. It deliberately does
not change the historic scalar ``reads``/``writes`` contract used by the CFG.
"""

from dataclasses import dataclass
from typing import Optional, Set, Tuple


ExpressionEffect = Tuple[str, Optional[str]]
_MUTATING_UNARY_OPS = frozenset({"++", "--", "p++", "p--"})


@dataclass(frozen=True)
class StorageEffect:
    """One ordered object/subobject read or write.

    ``member_path`` is empty for a scalar/whole-object binding and contains the
    selected member names for a struct/union access. ``access_path`` preserves
    each corresponding ``.``/``->`` operator so direct aggregate members stay
    distinguishable from pointer-member accesses. ``write_kind`` is populated
    for writes so consumers can distinguish initializers, plain assignments,
    compound assignments, and unary mutations.
    """

    action: str
    root: str
    member_path: Tuple[str, ...] = ()
    access_path: Tuple[str, ...] = ()
    write_kind: Optional[str] = None

    @property
    def is_direct_subobject(self) -> bool:
        return bool(self.member_path) and all(op == "." for op in self.access_path)


def _kind(node) -> str:
    return type(node).__name__ if node is not None else ""


def _direct_scalar_target(node) -> Optional[str]:
    if node is None:
        return None
    if _kind(node) == "ID":
        return str(node.name)
    if _kind(node) == "Cast":
        return _direct_scalar_target(node.expr)
    return None


def _direct_member_root(node) -> Optional[str]:
    """Return the aggregate root for a chain of direct ``.`` member accesses."""
    current = node
    while _kind(current) == "StructRef" and getattr(current, "type", None) == ".":
        current = current.name
    if _kind(current) == "ID":
        return str(current.name)
    return None


def _storage_target(node):
    """Return ``(root, member_path, access_path)`` for named storage targets."""
    if node is None:
        return None
    kind = _kind(node)
    if kind == "ID":
        return str(node.name), (), ()
    if kind == "Cast":
        return _storage_target(node.expr)
    if kind != "StructRef":
        return None

    base = _storage_target(node.name)
    field = getattr(getattr(node, "field", None), "name", None)
    access = getattr(node, "type", None)
    if base is None or not field or access not in {".", "->"}:
        return None
    root, member_path, access_path = base
    return root, member_path + (str(field),), access_path + (str(access),)


def _lvalue_address_effects(node) -> Tuple[ExpressionEffect, ...]:
    """Return effects required to locate an lvalue, excluding its stored value."""
    if node is None:
        return ()

    kind = _kind(node)
    if kind == "ID":
        return ()
    if kind == "Cast":
        return _lvalue_address_effects(node.expr)
    if kind == "ArrayRef":
        return _expression_effects(node.name) + _expression_effects(node.subscript)
    if kind == "StructRef":
        # Direct member selection only designates storage, so recursively walk
        # the lvalue base without turning nested ``a.b.c`` into a value read.
        # Pointer member selection must evaluate the pointer/base expression.
        if getattr(node, "type", None) == ".":
            return _lvalue_address_effects(node.name)
        return _expression_effects(node.name)
    if kind == "UnaryOp" and getattr(node, "op", None) == "*":
        return _expression_effects(node.expr)

    effects = []
    for _name, child in node.children():
        effects.extend(_expression_effects(child))
    return tuple(effects)


def _lvalue_value_effects(node) -> Tuple[ExpressionEffect, ...]:
    """Represent the old value read for compound/unary mutation."""
    target = _direct_scalar_target(node)
    if target is not None:
        return (("read", target),)

    # Direct member chains are not modeled as scalar writes to the aggregate,
    # but reading the previous member value still constitutes a use of the root
    # aggregate for CFG consumers such as dead-store analysis. Indirect lvalues
    # already expose pointer/index/base reads via their address effects.
    aggregate_root = _direct_member_root(node)
    if aggregate_root is not None:
        return (("read", aggregate_root),)

    return ()


def _expression_effects(node) -> Tuple[ExpressionEffect, ...]:
    if node is None:
        return ()

    kind = _kind(node)
    if kind == "ID":
        return (("read", str(node.name)),)
    if kind in {
        "Constant",
        "Typename",
        "EmptyStatement",
        "Break",
        "Continue",
        "Goto",
    }:
        return ()

    if kind == "Decl":
        initializer = getattr(node, "init", None)
        effects = list(_expression_effects(initializer))
        # Preserve the established CFG contract: an uninitialized declaration
        # is not a definition/write; an initializer is.
        if initializer is not None and getattr(node, "name", None):
            effects.append(("write", str(node.name)))
        return tuple(effects)

    if kind == "DeclList":
        effects = []
        for decl in getattr(node, "decls", ()) or ():
            effects.extend(_expression_effects(decl))
        return tuple(effects)

    if kind == "Assignment":
        # Use one deterministic CFG convention: evaluate the lvalue address,
        # then its old value for compound assignment, then RHS, and finally
        # commit the store.
        effects = list(_lvalue_address_effects(node.lvalue))
        if getattr(node, "op", "=") != "=":
            effects.extend(_lvalue_value_effects(node.lvalue))
        effects.extend(_expression_effects(node.rvalue))
        target = _direct_scalar_target(node.lvalue)
        effects.append(
            ("write", target) if target is not None else ("indirect_write", None)
        )
        return tuple(effects)

    if kind == "UnaryOp":
        op = getattr(node, "op", None)
        if op in _MUTATING_UNARY_OPS:
            effects = list(_lvalue_address_effects(node.expr))
            effects.extend(_lvalue_value_effects(node.expr))
            target = _direct_scalar_target(node.expr)
            effects.append(
                ("write", target) if target is not None else ("indirect_write", None)
            )
            return tuple(effects)
        # sizeof does not evaluate its operand's stored value (VLA size
        # expressions are still ignored here for object init purposes).
        if op == "sizeof":
            return ()
        return _expression_effects(node.expr)

    if kind == "StructRef":
        # Struct/union member names are not variables. The base expression is.
        return _expression_effects(node.name)

    if kind == "FuncCall":
        effects = list(_expression_effects(getattr(node, "name", None)))
        effects.extend(_expression_effects(getattr(node, "args", None)))
        return tuple(effects)

    if kind == "NamedInitializer":
        return _expression_effects(node.expr)

    if kind == "InitList":
        effects = []
        for expr in getattr(node, "exprs", ()) or ():
            effects.extend(_expression_effects(expr))
        return tuple(effects)

    if kind == "CompoundLiteral":
        return _expression_effects(getattr(node, "init", None))

    effects = []
    for _name, child in node.children():
        effects.extend(_expression_effects(child))
    return tuple(effects)


def _storage_lvalue_address_effects(node) -> Tuple[StorageEffect, ...]:
    """Return precise effects required only to locate an lvalue."""
    if node is None:
        return ()

    kind = _kind(node)
    if kind == "ID":
        return ()
    if kind == "Cast":
        return _storage_lvalue_address_effects(node.expr)
    if kind == "ArrayRef":
        return _storage_effects(node.name) + _storage_effects(node.subscript)
    if kind == "StructRef":
        if getattr(node, "type", None) == ".":
            return _storage_lvalue_address_effects(node.name)
        return _storage_effects(node.name)
    if kind == "UnaryOp" and getattr(node, "op", None) == "*":
        return _storage_effects(node.expr)

    effects = []
    for _name, child in node.children():
        effects.extend(_storage_effects(child))
    return tuple(effects)


def _storage_value_effect(node) -> Tuple[StorageEffect, ...]:
    target = _storage_target(node)
    if target is None:
        return ()
    root, member_path, access_path = target
    return (StorageEffect("read", root, member_path, access_path),)


def _storage_write_effect(node, write_kind: str) -> Tuple[StorageEffect, ...]:
    target = _storage_target(node)
    if target is None:
        return ()
    root, member_path, access_path = target
    return (
        StorageEffect(
            "write",
            root,
            member_path,
            access_path,
            write_kind=write_kind,
        ),
    )


def _storage_effects(node) -> Tuple[StorageEffect, ...]:
    """Return object-aware effects without collapsing direct member identity."""
    if node is None:
        return ()

    kind = _kind(node)
    if kind == "ID":
        return (StorageEffect("read", str(node.name)),)
    if kind in {
        "Constant",
        "Typename",
        "EmptyStatement",
        "Break",
        "Continue",
        "Goto",
    }:
        return ()

    if kind == "Decl":
        initializer = getattr(node, "init", None)
        effects = list(_storage_effects(initializer))
        if initializer is not None and getattr(node, "name", None):
            effects.append(
                StorageEffect("write", str(node.name), write_kind="initializer")
            )
        return tuple(effects)

    if kind == "DeclList":
        effects = []
        for decl in getattr(node, "decls", ()) or ():
            effects.extend(_storage_effects(decl))
        return tuple(effects)

    if kind == "Assignment":
        effects = list(_storage_lvalue_address_effects(node.lvalue))
        op = getattr(node, "op", "=")
        if op != "=":
            effects.extend(_storage_value_effect(node.lvalue))
        effects.extend(_storage_effects(node.rvalue))
        effects.extend(
            _storage_write_effect(
                node.lvalue,
                "plain" if op == "=" else "compound",
            )
        )
        return tuple(effects)

    if kind == "UnaryOp":
        op = getattr(node, "op", None)
        if op in _MUTATING_UNARY_OPS:
            effects = list(_storage_lvalue_address_effects(node.expr))
            effects.extend(_storage_value_effect(node.expr))
            effects.extend(_storage_write_effect(node.expr, "mutation"))
            return tuple(effects)
        if op == "sizeof":
            return ()
        return _storage_effects(node.expr)

    if kind == "StructRef":
        target = _storage_target(node)
        if target is not None:
            root, member_path, access_path = target
            return (StorageEffect("read", root, member_path, access_path),)
        return _storage_effects(node.name)

    if kind == "FuncCall":
        effects = list(_storage_effects(getattr(node, "name", None)))
        effects.extend(_storage_effects(getattr(node, "args", None)))
        return tuple(effects)

    if kind == "NamedInitializer":
        return _storage_effects(node.expr)

    if kind == "InitList":
        effects = []
        for expr in getattr(node, "exprs", ()) or ():
            effects.extend(_storage_effects(expr))
        return tuple(effects)

    if kind == "CompoundLiteral":
        return _storage_effects(getattr(node, "init", None))

    effects = []
    for _name, child in node.children():
        effects.extend(_storage_effects(child))
    return tuple(effects)


def ordered_expression_effects(node) -> Tuple[ExpressionEffect, ...]:
    """Return deterministic scalar expression effects in CFG evaluation order."""
    return _expression_effects(node)


def ordered_storage_effects(node) -> Tuple[StorageEffect, ...]:
    """Return deterministic object/subobject effects in CFG evaluation order."""
    return _storage_effects(node)


def expression_read_write_sets(node) -> Tuple[Set[str], Set[str]]:
    """Collapse ordered expression effects to the CFG's read/write set contract."""
    effects = ordered_expression_effects(node)
    reads = {
        name
        for action, name in effects
        if action == "read" and name is not None
    }
    writes = {
        name
        for action, name in effects
        if action == "write" and name is not None
    }
    return reads, writes


__all__ = [
    "ExpressionEffect",
    "StorageEffect",
    "expression_read_write_sets",
    "ordered_expression_effects",
    "ordered_storage_effects",
]
