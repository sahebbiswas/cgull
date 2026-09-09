"""Small affine-equality domain for CFG analyses.

The domain records facts of the form ``a == b + C`` plus exact scalar
constants.  It is deliberately conservative: joins retain only facts present
on every incoming path, unknown writes forget affected facts, and callers may
clear the domain around calls with unknown side effects.
"""

from dataclasses import dataclass
from typing import FrozenSet, Iterable, Optional, Tuple

from pycparser import c_ast


Relation = Tuple[str, str, int]
Constant = Tuple[str, int]


def _canonical(left: str, right: str, offset: int) -> Relation:
    """Store ``left == right + offset`` in a deterministic orientation."""
    if left < right:
        return left, right, offset
    return right, left, -offset


def _integer(node) -> Optional[int]:
    if isinstance(node, c_ast.Constant) and node.type == "int":
        token = node.value.rstrip("uUlL")
        try:
            return int(token, 8 if len(token) > 1 and token.startswith("0") and token.isdigit() else 0)
        except ValueError:
            return None
    if isinstance(node, c_ast.UnaryOp) and node.op in {"+", "-"}:
        value = _integer(node.expr)
        return None if value is None else value if node.op == "+" else -value
    if isinstance(node, c_ast.BinaryOp) and node.op in {"+", "-"}:
        left, right = _integer(node.left), _integer(node.right)
        if left is not None and right is not None:
            return left + right if node.op == "+" else left - right
    return None


def _affine_rhs(node):
    """Return (base-variable-or-None, offset) for a simple affine RHS."""
    value = _integer(node)
    if value is not None:
        return None, value
    if isinstance(node, c_ast.ID):
        return node.name, 0
    if isinstance(node, c_ast.BinaryOp) and node.op in {"+", "-"}:
        if isinstance(node.left, c_ast.ID):
            amount = _integer(node.right)
            if amount is not None:
                return node.left.name, amount if node.op == "+" else -amount
        if node.op == "+" and isinstance(node.right, c_ast.ID):
            amount = _integer(node.left)
            if amount is not None:
                return node.right.name, amount
    return None


@dataclass(frozen=True)
class AffineFacts:
    """Must-hold affine facts at one program point."""

    constants: FrozenSet[Constant] = frozenset()
    relations: FrozenSet[Relation] = frozenset()

    def constant(self, symbol: str) -> Optional[int]:
        for name, value in self.constants:
            if name == symbol:
                return value
        return None

    def offset(self, left: str, right: str) -> Optional[int]:
        """Return C when ``left == right + C`` is known."""
        if left == right:
            return 0
        key = _canonical(left, right, 0)[:2]
        for first, second, stored in self.relations:
            if (first, second) == key:
                return stored if left == first else -stored
        left_value, right_value = self.constant(left), self.constant(right)
        if left_value is not None and right_value is not None:
            return left_value - right_value
        return None

    def symbols_related_to(self, symbol: str) -> Iterable[Tuple[str, int]]:
        """Yield ``(other, C)`` where ``symbol == other + C``."""
        seen = {symbol}
        yield symbol, 0
        for first, second, stored in self.relations:
            if first == symbol and second not in seen:
                seen.add(second)
                yield second, stored
            elif second == symbol and first not in seen:
                seen.add(first)
                yield first, -stored

    def forget(self, symbol: str) -> "AffineFacts":
        return AffineFacts(
            frozenset((name, value) for name, value in self.constants if name != symbol),
            frozenset(rel for rel in self.relations if symbol not in rel[:2]),
        )

    def assign(self, symbol: str, rhs) -> "AffineFacts":
        parsed = _affine_rhs(rhs)
        facts = self.forget(symbol)
        if parsed is None:
            return facts
        base, offset = parsed
        constants = dict(facts.constants)
        relations = set(facts.relations)
        if base is None:
            constants[symbol] = offset
            for other, value in list(constants.items()):
                if other != symbol:
                    relations.add(_canonical(symbol, other, offset - value))
        else:
            base_value = facts.constant(base)
            if base_value is not None:
                constants[symbol] = base_value + offset
            if base != symbol:
                relations.add(_canonical(symbol, base, offset))
                # Preserve transitive equalities already known for the RHS base.
                for other, base_to_other in facts.symbols_related_to(base):
                    if other != symbol:
                        relations.add(_canonical(symbol, other, offset + base_to_other))
        return AffineFacts(frozenset(constants.items()), frozenset(relations))

    def shift(self, symbol: str, amount: int) -> "AffineFacts":
        constants = dict(self.constants)
        if symbol in constants:
            constants[symbol] += amount
        relations = set()
        for first, second, offset in self.relations:
            if first == symbol:
                offset += amount
            elif second == symbol:
                offset -= amount
            relations.add((first, second, offset))
        return AffineFacts(frozenset(constants.items()), frozenset(relations))


def join_affine(left: AffineFacts, right: AffineFacts) -> AffineFacts:
    """Must-join: retain only equalities established on every path."""
    return AffineFacts(left.constants & right.constants, left.relations & right.relations)


def transfer_affine(node, writes, facts: AffineFacts, *, has_unknown_call: bool = False) -> AffineFacts:
    """Apply one CFG event to affine facts.

    Only simple scalar declarations, assignments and +/- constant updates are
    modeled. Any other write forgets facts for the written symbol. Unknown
    calls clear the relation domain because pointer aliases may mutate locals.
    """
    if has_unknown_call:
        return AffineFacts()

    if isinstance(node, c_ast.DeclList):
        current = facts
        handled = set()
        for decl in node.decls or ():
            if decl.name:
                handled.add(decl.name)
            current = transfer_affine(decl, {decl.name} if decl.name else set(), current)
        for symbol in writes:
            if symbol not in handled:
                current = current.forget(symbol)
        return current

    handled = set()
    if isinstance(node, c_ast.Decl) and node.name:
        handled.add(node.name)
        facts = facts.assign(node.name, node.init) if node.init is not None else facts.forget(node.name)
    elif isinstance(node, c_ast.Assignment) and isinstance(node.lvalue, c_ast.ID):
        symbol = node.lvalue.name
        handled.add(symbol)
        if node.op == "=":
            facts = facts.assign(symbol, node.rvalue)
        elif node.op in {"+=", "-="}:
            amount = _integer(node.rvalue)
            if amount is None:
                facts = facts.forget(symbol)
            else:
                facts = facts.shift(symbol, amount if node.op == "+=" else -amount)
        else:
            facts = facts.forget(symbol)
    elif isinstance(node, c_ast.UnaryOp) and isinstance(node.expr, c_ast.ID):
        if node.op in {"++", "p++", "--", "p--"}:
            symbol = node.expr.name
            handled.add(symbol)
            facts = facts.shift(symbol, 1 if "+" in node.op else -1)

    for symbol in writes:
        if symbol not in handled:
            facts = facts.forget(symbol)
    return facts


__all__ = ["AffineFacts", "join_affine", "transfer_affine"]
