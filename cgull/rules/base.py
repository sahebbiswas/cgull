"""
Base Rule definitions for C-GULL Static Analyzer.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from ..models import Issue, Severity, RuleCategory, RuleDefinition, AnalysisEngine, FixType
import logging
from ..ast_analyzer import CASTContext

logger = logging.getLogger(__name__)



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
        source_lines: List[str],
        masked_line_content: str = "",
    ) -> List[Issue]:
        """
        Regex / lightweight line-by-line scanner.
        Override to implement pattern-based checks.

        `line_content` has comments stripped but string/char literal
        contents intact (so rules that need real string contents, e.g.
        detecting hardcoded secrets, still work correctly).

        `masked_line_content` additionally has string/char literal
        *contents* replaced with 'x' placeholders (quotes and length
        preserved). Call-pattern rules (banned functions, atoi, etc.)
        should match against this instead of `line_content` so that a
        function name appearing only as text inside a string literal --
        e.g. `char *msg = "please don't use gets()";` -- isn't mistaken
        for a real call. Defaults to "" for callers/tests that construct
        rules directly without going through CGullScanner.
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
        auto_fix_replacement: Optional[str] = None,
        fix_type: Optional[FixType] = None,
        suggested_fix_replacement: Optional[str] = None,
    ) -> Issue:
        if fix_type is None:
            if auto_fix_replacement is not None:
                fix_type = FixType.SAFE_FIX
            elif suggested_fix_replacement is not None:
                fix_type = FixType.SUGGESTED_FIX
            else:
                fix_type = FixType.MANUAL_REVIEW

        final_auto_fix = auto_fix_replacement if fix_type == FixType.SAFE_FIX else None
        final_suggested_fix = (
            suggested_fix_replacement
            if suggested_fix_replacement is not None
            else (auto_fix_replacement if fix_type == FixType.SUGGESTED_FIX else None)
        )

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
            auto_fix_replacement=final_auto_fix,
            fix_type=fix_type,
            suggested_fix_replacement=final_suggested_fix,
        )
