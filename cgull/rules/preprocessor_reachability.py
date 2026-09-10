"""Preprocessor branch reachability and redundancy diagnostics."""

from __future__ import annotations

from typing import List

from ..models import AnalysisEngine, Issue, RuleCategory, Severity
from ..preprocessor import (
    FALSE,
    TRUE,
    ConditionalBlock,
    Expression,
    conjunction,
    disjunction,
    format_expression,
    negate,
    parse_conditional_directives,
)
from ..preprocessor.robdd import implies, satisfiable
from .base import BaseRule


class PreprocessorReachabilityRule(BaseRule):
    """Report provably unreachable or redundant conditional branches."""

    rule_id = "CGULL-054"
    name = "Unreachable Preprocessor Branch"
    impact = Severity.LOW
    category = RuleCategory.CONTROL_FLOW
    description = (
        "Detect preprocessor branches that are provably unreachable or whose "
        "condition is guaranteed by the surrounding conditional context."
    )
    implementation_method = "Conditional directive IR and exact Boolean reasoning"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-561"
    remediation_suggestion = (
        "Remove unreachable branches or simplify redundant conditional directives "
        "while preserving the intended configuration behavior."
    )
    sample_vulnerable_code = "#if A\n#elif A\nint unreachable;\n#endif"
    sample_remediated_code = "#if A\nint enabled;\n#endif"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_line(
        self,
        file_path: str,
        line_number: int,
        line_content: str,
        full_code: str,
        source_lines: List[str],
        masked_line_content: str = "",
    ) -> List[Issue]:
        # The engine invokes lightweight rules once per physical line.  This is
        # a whole-file structural analysis, so run it exactly once.
        if line_number != 1:
            return []

        tree = parse_conditional_directives(full_code)
        issues: list[Issue] = []
        for block in tree.blocks:
            self._analyze_block(file_path, full_code, block, TRUE, issues)
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
                effective = remaining
                if not satisfiable(effective):
                    issues.append(
                        self._issue(
                            file_path,
                            source,
                            branch,
                            "Preprocessor #else branch is unreachable because "
                            f"the surrounding/earlier branch context is impossible "
                            f"({format_expression(effective)}).",
                        )
                    )
                self._analyze_children(file_path, source, branch.children, effective, issues)
                covered = TRUE
                continue

            condition = directive.condition
            # Malformed conditions carry no symbolic expression.  Do not make
            # claims about this branch or later siblings because their exact
            # chain context is then unknown.
            if condition is None:
                return

            effective = conjunction(remaining, condition)
            if not satisfiable(effective):
                issues.append(
                    self._issue(
                        file_path,
                        source,
                        branch,
                        "Preprocessor branch is unreachable: its condition "
                        f"'{directive.condition_text}' cannot be true when this "
                        f"branch is reached (effective condition: "
                        f"{format_expression(effective)}).",
                    )
                )
            elif implies(remaining, condition):
                issues.append(
                    self._issue(
                        file_path,
                        source,
                        branch,
                        "Preprocessor condition "
                        f"'{directive.condition_text}' is redundant: whenever this "
                        "branch is reached, the surrounding/earlier branch context "
                        f"already guarantees it ({format_expression(remaining)}).",
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

    def _issue(self, file_path: str, source: str, branch, message: str) -> Issue:
        directive = branch.directive
        location = directive.source_range.start
        return self.create_issue(
            file_path=file_path,
            line_number=location.line,
            column_number=location.column,
            code_snippet=directive.source_range.text(source),
            message=message,
            engine="Symbolic preprocessor",
        )
