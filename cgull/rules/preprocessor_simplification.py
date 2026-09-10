"""Preprocessor condition simplification diagnostics."""

from __future__ import annotations

from ..ast_analyzer import CASTContext
from ..models import AnalysisEngine, Issue, RuleCategory, Severity
from ..preprocessor import (
    FALSE,
    TRUE,
    ConditionalBlock,
    Conjunction,
    Disjunction,
    Expression,
    Negation,
    conjunction,
    disjunction,
    exact_simplify,
    format_expression,
    negate,
    parse_conditional_directives,
)
from ..preprocessor.robdd import equivalent, implies, satisfiable
from .base import BaseRule


def _expression_size(expression: Expression) -> int:
    if isinstance(expression, Negation):
        return 1 + _expression_size(expression.operand)
    if isinstance(expression, (Conjunction, Disjunction)):
        return 1 + sum(_expression_size(item) for item in expression.operands)
    return 1


def _simplify_under_context(expression: Expression, context: Expression) -> Expression:
    """Return a smaller expression equivalent whenever ``context`` holds.

    The exact ROBDD queries are used only to prove contextual substitutions.
    Returning the original expression is always safe when no proof is available.
    """
    expression = exact_simplify(expression)

    if implies(context, expression):
        return TRUE
    if implies(context, negate(expression)):
        return FALSE

    if isinstance(expression, Negation):
        operand = _simplify_under_context(expression.operand, context)
        candidate = exact_simplify(negate(operand))
    elif isinstance(expression, Conjunction):
        operands = []
        for operand in expression.operands:
            if implies(context, operand):
                continue
            if implies(context, negate(operand)):
                return FALSE
            operands.append(_simplify_under_context(operand, context))
        candidate = exact_simplify(conjunction(*operands))
    elif isinstance(expression, Disjunction):
        operands = []
        for operand in expression.operands:
            if implies(context, operand):
                return TRUE
            if implies(context, negate(operand)):
                continue
            operands.append(_simplify_under_context(operand, context))
        candidate = exact_simplify(disjunction(*operands))
    else:
        candidate = expression

    # A contextual rewrite must preserve the condition whenever this directive
    # can actually be reached. Resource exhaustion makes equivalent() return
    # False, so the fallback remains conservative.
    if equivalent(
        conjunction(context, expression),
        conjunction(context, candidate),
    ):
        return candidate
    return expression


class PreprocessorSimplificationRule(BaseRule):
    """Report semantically meaningful opportunities to simplify conditions."""

    rule_id = "CGULL-055"
    name = "Simplifiable Preprocessor Condition"
    impact = Severity.LOW
    category = RuleCategory.CONTROL_FLOW
    description = (
        "Detect preprocessor conditions whose Boolean structure can be expressed "
        "more simply, including simplifications implied by enclosing branches."
    )
    implementation_method = "Conditional directive IR and exact Boolean reasoning"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = None
    remediation_suggestion = (
        "Replace the condition with the suggested equivalent expression when it "
        "improves readability without obscuring configuration intent."
    )
    sample_vulnerable_code = "#if A || (A && B)\nint enabled;\n#endif"
    sample_remediated_code = "#if A\nint enabled;\n#endif"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> list[Issue]:
        return self._scan_source(file_path, ast_ctx.raw_source)

    def _scan_source(self, file_path: str, source: str) -> list[Issue]:
        tree = parse_conditional_directives(source)
        issues: list[Issue] = []
        for block in tree.blocks:
            self._analyze_block(file_path, source, block, TRUE, issues)
        return issues

    def _analyze_block(
        self,
        file_path: str,
        source: str,
        block: ConditionalBlock,
        parent_context: Expression,
        issues: list[Issue],
    ) -> None:
        covered: Expression = FALSE

        for branch in block.branches:
            directive = branch.directive
            remaining = conjunction(parent_context, negate(covered))

            if directive.kind == "else":
                if satisfiable(remaining):
                    self._analyze_children(
                        file_path, source, branch.children, remaining, issues
                    )
                covered = TRUE
                continue

            condition = directive.condition
            if condition is None:
                # Once a chain contains a malformed condition, the exact context
                # for later siblings is unknown.
                return

            effective = conjunction(remaining, condition)
            if not satisfiable(effective):
                covered = disjunction(covered, condition)
                continue

            original_size = _expression_size(condition)
            local = exact_simplify(condition)
            contextual = _simplify_under_context(local, remaining)

            # Reachability/redundancy diagnostics own conditions equivalent to
            # constant false/true in context. Avoid duplicate findings here.
            candidates = [item for item in (local, contextual) if item not in (TRUE, FALSE)]
            if candidates:
                suggested = min(
                    candidates,
                    key=lambda item: (_expression_size(item), format_expression(item)),
                )
                if _expression_size(suggested) < original_size and equivalent(
                    conjunction(remaining, condition),
                    conjunction(remaining, suggested),
                ):
                    issues.append(
                        self._issue(
                            file_path,
                            source,
                            branch,
                            directive.condition_text or format_expression(condition),
                            suggested,
                            contextual != local and suggested == contextual,
                        )
                    )

            self._analyze_children(file_path, source, branch.children, effective, issues)
            covered = disjunction(covered, condition)

    def _analyze_children(
        self,
        file_path: str,
        source: str,
        children: list[ConditionalBlock],
        parent_context: Expression,
        issues: list[Issue],
    ) -> None:
        for child in children:
            self._analyze_block(file_path, source, child, parent_context, issues)

    def _issue(
        self,
        file_path: str,
        source: str,
        branch,
        original: str,
        suggested: Expression,
        contextual: bool,
    ) -> Issue:
        directive = branch.directive
        location = directive.source_range.start
        qualifier = " under the surrounding branch context" if contextual else ""
        return self.create_issue(
            file_path=file_path,
            line_number=location.line,
            column_number=location.column,
            code_snippet=directive.source_range.text(source),
            message=(
                f"Preprocessor condition '{original}' can be simplified{qualifier} "
                f"to '{format_expression(suggested)}'."
            ),
            engine="Symbolic preprocessor",
        )
