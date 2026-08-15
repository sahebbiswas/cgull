"""
Base Rule definitions for C-GULL Static Analyzer.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from ..models import Issue, Severity, RuleCategory, RuleDefinition, AnalysisEngine
from ..ast_analyzer import CASTContext


class BaseRule(ABC):
    """
    Abstract base class for all C-GULL security and compliance rules.
    Rules can implement regex-based lightweight checks, AST-based semantic
    checks, or hybrid multi-pass checks.
    """

    rule_id: str = "CGULL-000"
    name: str = "Base Rule"
    impact: Severity = Severity.MEDIUM
    category: RuleCategory = RuleCategory.CONTROL_FLOW
    description: str = ""
    implementation_method: str = "Regex"
    implementation_complexity: str = "Low"
    chances_of_false_positives: str = "Low"
    cwe_id: str = "CWE-000"
    remediation_suggestion: str = ""
    sample_vulnerable_code: str = ""
    sample_remediated_code: str = ""
    analysis_engine: AnalysisEngine = AnalysisEngine.HYBRID

    def get_definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            name=self.name,
            impact=self.impact,
            category=self.category,
            description=self.description,
            implementation_method=self.implementation_method,
            implementation_complexity=self.implementation_complexity,
            chances_of_false_positives=self.chances_of_false_positives,
            cwe_id=self.cwe_id,
            remediation_suggestion=self.remediation_suggestion,
            sample_vulnerable_code=self.sample_vulnerable_code,
            sample_remediated_code=self.sample_remediated_code,
            analysis_engine=self.analysis_engine,
        )

    def scan_line(
        self,
        file_path: str,
        line_number: int,
        line_content: str,
        full_code: str,
        source_lines: List[str]
    ) -> List[Issue]:
        """
        Regex / lightweight line-by-line scanner.
        Override to implement pattern-based checks.
        """
        return []

    def scan_ast(
        self,
        file_path: str,
        ast_ctx: CASTContext
    ) -> List[Issue]:
        """
        AST / semantic graph scanner.
        Override to implement AST or pycparser-based checks.
        """
        return []

    def create_issue(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        message: str,
        column_number: int = 1,
        engine: str = "Regex",
        auto_fix_replacement: Optional[str] = None
    ) -> Issue:
        return Issue(
            rule_id=self.rule_id,
            rule_name=self.name,
            impact=self.impact,
            file_path=file_path,
            line_number=line_number,
            column_number=column_number,
            code_snippet=code_snippet.strip(),
            message=message,
            remediation=self.remediation_suggestion,
            cwe_id=self.cwe_id,
            engine=engine,
            auto_fix_replacement=auto_fix_replacement,
        )
