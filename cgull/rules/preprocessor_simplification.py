"""Preprocessor condition simplification diagnostics."""

from __future__ import annotations

from ..ast_analyzer import CASTContext
from ..models import AnalysisEngine, Issue, RuleCategory, Severity
from ..preprocessor import parse_conditional_directives
from ..preprocessor.branch_analysis import (
    BranchAnalysis,
    BranchStatus,
    analyze_conditional_tree,
)
from .base import BaseRule


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
    cwe_id = "CWE-000"
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
        for analysis in analyze_conditional_tree(tree):
            if analysis.status == BranchStatus.SIMPLIFIED:
                issues.append(self._issue(file_path, source, analysis))
        return issues

    def _issue(self, file_path: str, source: str, analysis: BranchAnalysis) -> Issue:
        branch = analysis.branch
        directive = branch.directive
        location = directive.source_range.start
        qualifier = (
            " under the surrounding branch context"
            if analysis.contextual_simplification
            else ""
        )
        original = directive.condition_text
        return self.create_issue(
            file_path=file_path,
            line_number=location.line,
            column_number=location.column,
            code_snippet=directive.source_range.text(source),
            message=(
                f"Preprocessor condition '{original}' can be simplified{qualifier} "
                f"to '{analysis.simplified_condition_text}'."
            ),
            engine="Symbolic preprocessor",
        )
