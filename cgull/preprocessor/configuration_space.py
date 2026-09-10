"""Derive deterministic witness configurations for preprocessor branches."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .directives import ConditionalBlock, ConditionalBranch, ConditionalTree
from .expressions import (
    FALSE,
    TRUE,
    BooleanAtom,
    Defined,
    Expression,
    Predicate,
    Variable,
    conjunction,
    disjunction,
    expression_atoms,
    negate,
)
from .robdd import AnalysisLimitExceeded, BDD, ResourceLimits


class WitnessStatus(str, Enum):
    """Outcome of witness derivation for one conditional branch."""

    SATISFIABLE = "satisfiable"
    UNREACHABLE = "unreachable"
    UNSUPPORTED = "unsupported"
    LIMIT_EXCEEDED = "limit_exceeded"


@dataclass(frozen=True)
class WitnessAssignment:
    """One Boolean term in a branch witness.

    ``macro_value`` represents truth of a bare macro expression, ``defined``
    represents macro definedness, and ``predicate`` retains an opaque
    value-bearing expression without inventing an integer value for it.
    """

    kind: str
    key: str
    value: bool


@dataclass(frozen=True)
class BranchWitness:
    """Witness-analysis result for one branch in source order."""

    branch: ConditionalBranch
    effective_condition: Expression | None
    status: WitnessStatus
    assignments: tuple[WitnessAssignment, ...] = ()
    limit_resource: str | None = None
    limit_value: int | None = None
    limit_observed: int | None = None

    @property
    def has_witness(self) -> bool:
        return self.status is WitnessStatus.SATISFIABLE


def _assignment(atom: BooleanAtom, value: bool) -> WitnessAssignment:
    if isinstance(atom, Defined):
        return WitnessAssignment("defined", atom.name, value)
    if isinstance(atom, Variable):
        return WitnessAssignment("macro_value", atom.name, value)
    if isinstance(atom, Predicate):
        return WitnessAssignment("predicate", atom.text, value)
    raise TypeError("unsupported Boolean atom")


def _solve(
    branch: ConditionalBranch,
    expression: Expression,
    limits: ResourceLimits | None,
) -> BranchWitness:
    try:
        bdd = BDD(expression_atoms(expression), limits=limits)
        root = bdd.build(expression)
        if root == 0:
            return BranchWitness(branch, expression, WitnessStatus.UNREACHABLE)
        witness = bdd.witness(root)
        assert witness is not None
        assignments = tuple(
            _assignment(atom, value) for atom, value in witness.items()
        )
        return BranchWitness(
            branch,
            expression,
            WitnessStatus.SATISFIABLE,
            assignments,
        )
    except AnalysisLimitExceeded as exc:
        return BranchWitness(
            branch,
            expression,
            WitnessStatus.LIMIT_EXCEEDED,
            limit_resource=exc.resource,
            limit_value=exc.limit,
            limit_observed=exc.observed,
        )


def _append_unsupported(
    block: ConditionalBlock,
    results: list[BranchWitness],
) -> None:
    for branch in block.branches:
        results.append(BranchWitness(branch, None, WitnessStatus.UNSUPPORTED))
        for child in branch.children:
            _append_unsupported(child, results)


def _walk_block(
    block: ConditionalBlock,
    parent_context: Expression,
    limits: ResourceLimits | None,
    results: list[BranchWitness],
) -> None:
    covered: Expression = FALSE
    chain_supported = True

    for branch in block.branches:
        directive = branch.directive
        if not chain_supported:
            results.append(BranchWitness(branch, None, WitnessStatus.UNSUPPORTED))
            for child in branch.children:
                _append_unsupported(child, results)
            continue

        remaining = conjunction(parent_context, negate(covered))
        if directive.kind == "else":
            effective = remaining
            result = _solve(branch, effective, limits)
            results.append(result)
            for child in branch.children:
                _walk_block(child, effective, limits, results)
            covered = TRUE
            continue

        condition = directive.condition
        if condition is None:
            results.append(BranchWitness(branch, None, WitnessStatus.UNSUPPORTED))
            for child in branch.children:
                _append_unsupported(child, results)
            chain_supported = False
            continue

        effective = conjunction(remaining, condition)
        result = _solve(branch, effective, limits)
        results.append(result)
        for child in branch.children:
            _walk_block(child, effective, limits, results)
        covered = disjunction(covered, condition)


def derive_branch_witnesses(
    tree: ConditionalTree,
    *,
    limits: ResourceLimits | None = None,
) -> tuple[BranchWitness, ...]:
    """Return branch witnesses in deterministic source/preorder traversal.

    Effective conditions include enclosing branch constraints and all prior
    alternatives in the same ``#if``/``#elif``/``#else`` chain. Malformed
    conditions are reported as ``UNSUPPORTED`` rather than guessed. ROBDD
    resource exhaustion is reported separately from logical unreachability.
    """

    results: list[BranchWitness] = []
    for block in tree.blocks:
        _walk_block(block, TRUE, limits, results)
    return tuple(results)


__all__ = [
    "WitnessStatus",
    "WitnessAssignment",
    "BranchWitness",
    "derive_branch_witnesses",
]
