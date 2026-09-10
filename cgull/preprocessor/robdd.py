"""Exact Boolean queries for symbolic preprocessor conditions.

The ROBDD model deliberately treats ``Variable``, ``Defined`` and ``Predicate``
as independent Boolean atoms.  In particular, opaque value-bearing predicates
are never interpreted as C integer expressions.

Atom order is the same deterministic structural order used by
:func:`cgull.preprocessor.ordered_atoms`: ``Defined`` atoms first, then opaque
``Predicate`` atoms, then ``Variable`` atoms, with each class ordered by its
text/name.  A single manager uses that order for every operand in a query.

Public query helpers fail conservatively when a resource limit is exceeded:
``satisfiable`` returns ``True`` (it will not claim dead code), ``equivalent``
and ``implies`` return ``False`` (they will not claim a proof), and
``witness_assignment`` returns ``None``.  ``exact_simplify`` falls back to the
existing algebraic simplifier.  The lower-level :class:`BDD` API raises
:class:`AnalysisLimitExceeded` so callers that need diagnostics can distinguish
resource exhaustion from a logical result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .expressions import (
    BooleanAtom,
    Conjunction,
    Constant,
    Defined,
    Disjunction,
    Expression,
    FALSE,
    Negation,
    Predicate,
    TRUE,
    Variable,
    _sort_key,
    conjunction,
    disjunction,
    expression_atoms,
    negate,
    simplify,
)


@dataclass(frozen=True)
class ResourceLimits:
    """Deterministic structural limits for one ROBDD analysis."""

    max_atoms: int = 64
    max_bdd_nodes: int = 100_000
    max_work: int = 500_000

    def __post_init__(self) -> None:
        for name in ("max_atoms", "max_bdd_nodes", "max_work"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


class AnalysisLimitExceeded(RuntimeError):
    """A deterministic ROBDD resource limit was exceeded."""

    def __init__(self, resource: str, limit: int, observed: int):
        self.resource = resource
        self.limit = limit
        self.observed = observed
        super().__init__(
            f"analysis limit exceeded for {resource}: {observed} > {limit}"
        )


class _Budget:
    def __init__(self, limit: int):
        self.limit = limit
        self.work = 0

    def consume(self) -> None:
        self.work += 1
        if self.work > self.limit:
            raise AnalysisLimitExceeded("work", self.limit, self.work)


class BDD:
    """Reduced ordered binary decision diagram manager.

    Node ids 0 and 1 are the false and true terminals.  Non-terminal nodes are
    triples ``(atom_index, low, high)`` interned in a unique table, which makes
    roots canonical for one fixed atom order.
    """

    def __init__(
        self,
        atoms: Iterable[BooleanAtom],
        *,
        limits: ResourceLimits | None = None,
    ) -> None:
        self.limits = limits or ResourceLimits()
        ordered = tuple(sorted(set(atoms), key=_sort_key))
        if len(ordered) > self.limits.max_atoms:
            raise AnalysisLimitExceeded(
                "atoms", self.limits.max_atoms, len(ordered)
            )
        self.atoms = ordered
        self.order = {atom: index for index, atom in enumerate(ordered)}
        self.nodes: list[tuple[int, int, int] | None] = [None, None]
        self.unique: dict[tuple[int, int, int], int] = {}
        self._budget = _Budget(self.limits.max_work)
        self._apply_cache: dict[tuple[str, int, int], int] = {}
        self._not_cache: dict[int, int] = {0: 1, 1: 0}
        self._build_cache: dict[Expression, int] = {}
        self._expression_cache: dict[int, Expression] = {0: FALSE, 1: TRUE}

    def _consume(self) -> None:
        self._budget.consume()

    def _node(self, variable: int, low: int, high: int) -> int:
        if low == high:
            return low
        key = (variable, low, high)
        existing = self.unique.get(key)
        if existing is not None:
            return existing
        self._consume()
        observed = len(self.nodes) - 1
        if observed > self.limits.max_bdd_nodes:
            raise AnalysisLimitExceeded(
                "bdd_nodes", self.limits.max_bdd_nodes, observed
            )
        node = len(self.nodes)
        self.nodes.append(key)
        self.unique[key] = node
        return node

    def build(self, expression: Expression) -> int:
        expression = simplify(expression)
        cached = self._build_cache.get(expression)
        if cached is not None:
            return cached
        self._consume()
        if isinstance(expression, Constant):
            result = int(expression.value)
        elif isinstance(expression, (Variable, Defined, Predicate)):
            result = self._node(self.order[expression], 0, 1)
        elif isinstance(expression, Negation):
            result = self.negate(self.build(expression.operand))
        elif isinstance(expression, Conjunction):
            result = 1
            for operand in expression.operands:
                result = self.apply("and", result, self.build(operand))
        elif isinstance(expression, Disjunction):
            result = 0
            for operand in expression.operands:
                result = self.apply("or", result, self.build(operand))
        else:  # defensive guard for future Expression variants
            raise TypeError("unsupported symbolic expression")
        self._build_cache[expression] = result
        return result

    def negate(self, node: int) -> int:
        cached = self._not_cache.get(node)
        if cached is not None:
            return cached
        self._consume()
        item = self.nodes[node]
        assert item is not None
        variable, low, high = item
        result = self._node(variable, self.negate(low), self.negate(high))
        self._not_cache[node] = result
        return result

    def apply(self, operation: str, left: int, right: int) -> int:
        if operation not in ("and", "or"):
            raise ValueError(f"unknown BDD operation: {operation}")
        if left > right:
            left, right = right, left
        key = (operation, left, right)
        cached = self._apply_cache.get(key)
        if cached is not None:
            return cached
        self._consume()
        if operation == "and":
            if left == 0 or right == 0:
                return 0
            if left == 1:
                return right
            if left == right:
                return left
        else:
            if left == 1 or right == 1:
                return 1
            if left == 0:
                return right
            if left == right:
                return left

        left_node = self.nodes[left]
        right_node = self.nodes[right]
        assert left_node is not None and right_node is not None
        variable = min(left_node[0], right_node[0])
        left_low, left_high = (
            (left_node[1], left_node[2])
            if left_node[0] == variable else (left, left)
        )
        right_low, right_high = (
            (right_node[1], right_node[2])
            if right_node[0] == variable else (right, right)
        )
        result = self._node(
            variable,
            self.apply(operation, left_low, right_low),
            self.apply(operation, left_high, right_high),
        )
        self._apply_cache[key] = result
        return result

    def to_expression(self, node: int) -> Expression:
        cached = self._expression_cache.get(node)
        if cached is not None:
            return cached
        self._consume()
        item = self.nodes[node]
        assert item is not None
        variable_index, low_node, high_node = item
        atom = self.atoms[variable_index]
        low = self.to_expression(low_node)
        high = self.to_expression(high_node)
        if low == FALSE:
            result = conjunction(atom, high)
        elif high == FALSE:
            result = conjunction(negate(atom), low)
        elif low == TRUE:
            result = disjunction(negate(atom), high)
        elif high == TRUE:
            result = disjunction(atom, low)
        else:
            result = disjunction(
                conjunction(negate(atom), low),
                conjunction(atom, high),
            )
        self._expression_cache[node] = result
        return result

    def witness(self, root: int) -> dict[BooleanAtom, bool] | None:
        """Return the lexicographically deterministic false-first witness."""
        if root == 0:
            return None
        assignment: dict[BooleanAtom, bool] = {}
        node = root
        while node >= 2:
            self._consume()
            item = self.nodes[node]
            assert item is not None
            variable, low, high = item
            atom = self.atoms[variable]
            if low != 0:
                assignment[atom] = False
                node = low
            else:
                assignment[atom] = True
                node = high
        if node == 0:
            return None
        # Reduced BDDs may skip don't-care variables; fill them deterministically.
        return {atom: assignment.get(atom, False) for atom in self.atoms}


def _atoms(*expressions: Expression) -> tuple[BooleanAtom, ...]:
    atoms: set[BooleanAtom] = set()
    for expression in expressions:
        atoms.update(expression_atoms(expression))
    return tuple(sorted(atoms, key=_sort_key))


def _manager(*expressions: Expression, limits: ResourceLimits | None = None) -> BDD:
    return BDD(_atoms(*expressions), limits=limits)


def equivalent(
    left: Expression,
    right: Expression,
    *,
    limits: ResourceLimits | None = None,
) -> bool:
    """Return whether two expressions are semantically equivalent.

    Resource exhaustion returns ``False`` rather than claiming equivalence.
    """
    try:
        bdd = _manager(left, right, limits=limits)
        return bdd.build(left) == bdd.build(right)
    except AnalysisLimitExceeded:
        return False


def satisfiable(
    expression: Expression,
    *,
    limits: ResourceLimits | None = None,
) -> bool:
    """Return whether an expression has a Boolean assignment.

    Resource exhaustion returns ``True`` rather than incorrectly declaring an
    expression impossible/dead.
    """
    try:
        bdd = _manager(expression, limits=limits)
        return bdd.build(expression) != 0
    except AnalysisLimitExceeded:
        return True


def implies(
    premise: Expression,
    consequence: Expression,
    *,
    limits: ResourceLimits | None = None,
) -> bool:
    """Return whether ``premise`` logically implies ``consequence``.

    Resource exhaustion returns ``False`` rather than claiming a proof.
    """
    try:
        bdd = _manager(premise, consequence, limits=limits)
        premise_node = bdd.build(premise)
        consequence_node = bdd.build(consequence)
        counterexample = bdd.apply(
            "and", premise_node, bdd.negate(consequence_node)
        )
        return counterexample == 0
    except AnalysisLimitExceeded:
        return False


def witness_assignment(
    expression: Expression,
    *,
    limits: ResourceLimits | None = None,
) -> dict[BooleanAtom, bool] | None:
    """Return a deterministic satisfying assignment, or ``None``.

    ``None`` means either that the expression is unsatisfiable or that resource
    limits prevented a safe witness from being produced.  Callers that need to
    distinguish those cases can use :class:`BDD` directly.
    """
    try:
        bdd = _manager(expression, limits=limits)
        return bdd.witness(bdd.build(expression))
    except AnalysisLimitExceeded:
        return None


def _expression_size(expression: Expression) -> int:
    if isinstance(expression, (Constant, Variable, Defined, Predicate)):
        return 1
    if isinstance(expression, Negation):
        return 1 + _expression_size(expression.operand)
    return 1 + sum(_expression_size(item) for item in expression.operands)


def exact_simplify(
    expression: Expression,
    *,
    limits: ResourceLimits | None = None,
) -> Expression:
    """Use ROBDD equivalence to choose a smaller equivalent expression.

    The algebraic simplifier remains the fallback when the canonical ROBDD form
    is not smaller or resource limits are exceeded.
    """
    algebraic = simplify(expression)
    try:
        bdd = _manager(algebraic, limits=limits)
        canonical = bdd.to_expression(bdd.build(algebraic))
    except AnalysisLimitExceeded:
        return algebraic
    return canonical if _expression_size(canonical) < _expression_size(algebraic) else algebraic


__all__ = [
    "AnalysisLimitExceeded",
    "BDD",
    "ResourceLimits",
    "equivalent",
    "satisfiable",
    "implies",
    "witness_assignment",
    "exact_simplify",
]
