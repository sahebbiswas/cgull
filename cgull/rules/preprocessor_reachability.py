"""Preprocessor branch reachability and redundancy diagnostics."""

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
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> list[Issue]:
        # raw_source retains the complete directive structure. clean_source may
        # already have selected/stripped branches and is unsuitable here.
        return self._scan_source(file_path, ast_ctx.raw_source)

    def _scan_source(self, file_path: str, source: str) -> list[Issue]:
        tree = parse_conditional_directives(source)
        issues: list[Issue] = []
        for analysis in analyze_conditional_tree(tree):
            if analysis.status in (BranchStatus.DEAD, BranchStatus.REDUNDANT):
                issues.append(self._issue(file_path, source, analysis))
        return issues

    def _issue(self, file_path: str, source: str, analysis: BranchAnalysis) -> Issue:
        branch = analysis.branch
        directive = branch.directive
        location = directive.source_range.start

        if analysis.status == BranchStatus.DEAD:
            if directive.kind == "else":
                message = (
                    "Preprocessor #else branch is unreachable because "
                    "the surrounding/earlier branch context is impossible "
                    f"({analysis.effective_condition_text})."
                )
            else:
                message = (
                    "Preprocessor branch is unreachable: its condition "
                    f"'{directive.condition_text}' cannot be true when this "
                    "branch is reached (effective condition: "
                    f"{analysis.effective_condition_text})."
                )
        else:
            message = (
                "Preprocessor condition "
                f"'{directive.condition_text}' is redundant: whenever this "
                "branch is reached, the surrounding/earlier branch context "
                f"already guarantees it ({analysis.context_text})."
            )

        return self.create_issue(
            file_path=file_path,
            line_number=location.line,
            column_number=location.column,
            code_snippet=directive.source_range.text(source),
            message=message,
            engine="Symbolic preprocessor",
        )
