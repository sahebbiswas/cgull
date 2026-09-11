"""Shared semantic analysis for conditional-preprocessor branches.

This module is intentionally presentation-agnostic. Scanner rules and CLI
reporting consume the same branch facts so reachability, redundancy and
simplification decisions cannot drift between interfaces.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .directives import ConditionalBlock, ConditionalBranch, ConditionalTree
from .expressions import (
    FALSE,
    TRUE,
    Conjunction,
    Disjunction,
    Expression,
    Negation,
    conjunction,
    disjunction,
    exact_simplify,
    format_expression,
    negate,
)
from .robdd import equivalent, implies, satisfiable


class BranchStatus(str, Enum):
    """Semantic classification of one conditional branch."""

    DEAD = "dead"
    REDUNDANT = "redundant"
    SIMPLIFIED = "simplified"
    UNCHANGED = "unchanged"


class Reachability(str, Enum):
    """Reachability state for a conditional branch."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class BranchAnalysis:
    """Presentation-neutral semantic facts for one conditional branch."""

    branch: ConditionalBranch
    status: BranchStatus
    reachability: Reachability
    context: Expression
    effective_condition: Expression | None
    simplified_condition: Expression | None = None
    contextual_simplification: bool = False

    @property
    def original_condition(self) -> str | None:
        return self.branch.directive.condition_text

    @property
    def context_text(self) -> str:
        return format_expression(self.context)

    @property
    def effective_condition_text(self) -> str | None:
        if self.effective_condition is None:
            return None
        return format_expression(self.effective_condition)

    @property
    def simplified_condition_text(self) -> str | None:
        if self.simplified_condition is None:
            return None
        return format_expression(self.simplified_condition)


def expression_size(expression: Expression) -> int:
    """Return a simple structural size used to require meaningful rewrites."""

    if isinstance(expression, Negation):
        return 1 + expression_size(expression.operand)
    if isinstance(expression, (Conjunction, Disjunction)):
        return 1 + sum(expression_size(item) for item in expression.operands)
    return 1


def simplify_under_context(expression: Expression, context: Expression) -> Expression:
    """Return a smaller condition proven equivalent whenever ``context`` holds."""

    expression = exact_simplify(expression)

    if implies(context, expression):
        return TRUE
    if implies(context, negate(expression)):
        return FALSE

    if isinstance(expression, Negation):
        operand = simplify_under_context(expression.operand, context)
        candidate = exact_simplify(negate(operand))
    elif isinstance(expression, Conjunction):
        operands = []
        for operand in expression.operands:
            if implies(context, operand):
                continue
            if implies(context, negate(operand)):
                return FALSE
            operands.append(simplify_under_context(operand, context))
        candidate = exact_simplify(conjunction(*operands))
    elif isinstance(expression, Disjunction):
        operands = []
        for operand in expression.operands:
            if implies(context, operand):
                return TRUE
            if implies(context, negate(operand)):
                continue
            operands.append(simplify_under_context(operand, context))
        candidate = exact_simplify(disjunction(*operands))
    else:
        candidate = expression

    if equivalent(
        conjunction(context, expression),
        conjunction(context, candidate),
    ):
        return candidate
    return expression


def analyze_conditional_tree(tree: ConditionalTree) -> list[BranchAnalysis]:
    """Analyze every structurally reachable branch in deterministic source order."""

    analyses: list[BranchAnalysis] = []
    for block in tree.blocks:
        _analyze_block(block, TRUE, analyses)
    return analyses


def _analyze_block(
    block: ConditionalBlock,
    parent_context: Expression,
    analyses: list[BranchAnalysis],
) -> None:
    covered: Expression = FALSE

    for branch in block.branches:
        directive = branch.directive
        remaining = conjunction(parent_context, negate(covered))

        if directive.kind == "else":
            effective = remaining
            reachable = satisfiable(effective)
            analyses.append(
                BranchAnalysis(
                    branch=branch,
                    status=BranchStatus.UNCHANGED if reachable else BranchStatus.DEAD,
                    reachability=(
                        Reachability.REACHABLE if reachable else Reachability.UNREACHABLE
                    ),
                    context=remaining,
                    effective_condition=effective,
                )
            )
            if reachable:
                _analyze_children(branch, effective, analyses)
            covered = TRUE
            continue

        condition = directive.condition
        if condition is None:
            analyses.append(
                BranchAnalysis(
                    branch=branch,
                    status=BranchStatus.UNCHANGED,
                    reachability=Reachability.UNKNOWN,
                    context=remaining,
                    effective_condition=None,
                )
            )
            # Later sibling context is unknowable after a malformed condition.
            return

        effective = conjunction(remaining, condition)
        reachable = satisfiable(effective)
        status = BranchStatus.UNCHANGED
        simplified = None
        contextual_simplification = False

        if not reachable:
            status = BranchStatus.DEAD
            reachability = Reachability.UNREACHABLE
        else:
            reachability = Reachability.REACHABLE
            if implies(remaining, condition):
                status = BranchStatus.REDUNDANT
            else:
                original_size = expression_size(condition)
                local = exact_simplify(condition)
                contextual = simplify_under_context(local, remaining)
                candidates = [item for item in (local, contextual) if item not in (TRUE, FALSE)]
                if candidates:
                    candidate = min(
                        candidates,
                        key=lambda item: (expression_size(item), format_expression(item)),
                    )
                    if expression_size(candidate) < original_size and equivalent(
                        conjunction(remaining, condition),
                        conjunction(remaining, candidate),
                    ):
                        status = BranchStatus.SIMPLIFIED
                        simplified = candidate
                        contextual_simplification = contextual != local and candidate == contextual

        analyses.append(
            BranchAnalysis(
                branch=branch,
                status=status,
                reachability=reachability,
                context=remaining,
                effective_condition=effective,
                simplified_condition=simplified,
                contextual_simplification=contextual_simplification,
            )
        )

        if reachable:
            _analyze_children(branch, effective, analyses)
        covered = disjunction(covered, condition)


def _analyze_children(
    branch: ConditionalBranch,
    parent_context: Expression,
    analyses: list[BranchAnalysis],
) -> None:
    for child in branch.children:
        _analyze_block(child, parent_context, analyses)
