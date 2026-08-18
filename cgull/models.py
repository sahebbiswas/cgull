"""
Data models for C-GULL Static Analyzer.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import time
from . import __version__


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AnalysisEngine(str, Enum):
    REGEX = "Regex"
    AST = "AST"
    HYBRID = "Hybrid"


class FixType(str, Enum):
    SAFE_FIX = "safe_fix"
    SUGGESTED_FIX = "suggested_fix"
    MANUAL_REVIEW = "manual_review"


class ParserStatus(str, Enum):
    PYCPARSER_SUCCESS = "pycparser-success"
    FALLBACK_PARSER = "fallback-parser"
    PARSE_FAILED = "parse-failed"


class Confidence(str, Enum):
    FULL = "FULL"
    FALLBACK = "FALLBACK"
    LIMITED = "LIMITED"


class RuleCategory(str, Enum):
    MEMORY = "Memory Management & Allocation"
    STRINGS = "String Operations & Bounds"
    CONTROL_FLOW = "Control Flow & Logic"
    ARITHMETIC = "Arithmetic & Types"
    CRYPTO = "Cryptography & Timing"
    STYLE = "Code Quality & MISRA-C"


@dataclass
class RuleDefinition:
    rule_id: str
    name: str
    impact: Severity
    category: RuleCategory
    description: str
    implementation_method: str
    implementation_complexity: str
    chances_of_false_positives: str
    cwe_id: str
    remediation_suggestion: str
    sample_vulnerable_code: str
    sample_remediated_code: str
    analysis_engine: AnalysisEngine = AnalysisEngine.HYBRID

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "impact": self.impact.value,
            "category": self.category.value,
            "description": self.description,
            "implementation_method": self.implementation_method,
            "implementation_complexity": self.implementation_complexity,
            "chances_of_false_positives": self.chances_of_false_positives,
            "cwe_id": self.cwe_id,
            "remediation_suggestion": self.remediation_suggestion,
            "sample_vulnerable_code": self.sample_vulnerable_code,
            "sample_remediated_code": self.sample_remediated_code,
            "analysis_engine": self.analysis_engine.value,
        }


@dataclass
class Issue:
    rule_id: str
    rule_name: str
    impact: Severity
    file_path: str
    line_number: int
    column_number: int = 1
    code_snippet: str = ""
    message: str = ""
    remediation: str = ""
    cwe_id: str = ""
    engine: str = "Regex"
    auto_fix_replacement: Optional[str] = None
    fingerprint: str = ""
    fix_type: FixType = FixType.MANUAL_REVIEW
    suggested_fix_replacement: Optional[str] = None
    confidence: Optional[Confidence] = None

    def to_dict(self) -> Dict[str, Any]:
        conf_val = self.confidence.value if isinstance(self.confidence, Confidence) else (str(self.confidence) if self.confidence else None)
        d = {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "impact": self.impact.value if isinstance(self.impact, Severity) else str(self.impact),
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "code_snippet": self.code_snippet,
            "message": self.message,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "engine": self.engine,
            "fix_type": self.fix_type.value if isinstance(self.fix_type, FixType) else str(self.fix_type),
            "auto_fix_replacement": self.auto_fix_replacement,
            "suggested_fix_replacement": self.suggested_fix_replacement,
            "fingerprint": self.fingerprint,
        }
        if conf_val:
            d["confidence"] = conf_val
        return d


@dataclass
class FileScanSummary:
    file_path: str
    lines_of_code: int
    issues_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_duration_ms: float
    parser: str = ParserStatus.FALLBACK_PARSER.value
    status: str = "success"
    confidence: str = Confidence.FALLBACK.value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target_path: str
    scanned_files_count: int
    total_lines_of_code: int
    total_issues_count: int
    high_severity_count: int
    medium_severity_count: int
    low_severity_count: int
    scan_duration_seconds: float
    timestamp: str
    issues: List[Issue] = field(default_factory=list)
    file_summaries: List[FileScanSummary] = field(default_factory=list)
    ignored_paths: List[str] = field(default_factory=list)
    failed_paths: List[str] = field(default_factory=list)
    files_discovered: int = 0
    files_analyzed: int = 0
    files_ignored: int = 0
    files_failed: int = 0
    analysis_status_counts: Dict[str, int] = field(default_factory=dict)
    overall_parser_status: Optional[str] = None
    overall_analysis_status: Optional[str] = None
    rules_applied: int = 0
    # Populated only when a --baseline was applied (see cgull.baseline);
    # left at their defaults for an ordinary, non-baseline scan.
    is_baseline_filtered: bool = False
    baseline_new_count: Optional[int] = None
    baseline_resolved_count: Optional[int] = None
    baseline_total_before_filter: Optional[int] = None

    def get_overall_parser_status(self) -> str:
        if self.overall_parser_status:
            return self.overall_parser_status
        if self.analysis_status_counts.get(ParserStatus.PYCPARSER_SUCCESS.value, 0) > 0:
            if self.analysis_status_counts.get(ParserStatus.FALLBACK_PARSER.value, 0) > 0:
                return "hybrid"
            return "pycparser"
        elif self.analysis_status_counts.get(ParserStatus.FALLBACK_PARSER.value, 0) > 0:
            return "fallback-parser"
        return "regex"

    def get_overall_analysis_status(self) -> str:
        if self.overall_analysis_status:
            return self.overall_analysis_status
        if self.files_failed == 0:
            return "success"
        elif self.files_analyzed > 0:
            return "partial_success"
        return "failed"

    def to_dict(self) -> Dict[str, Any]:
        analysis: Dict[str, Any] = {
            "parser": self.get_overall_parser_status(),
            "status": self.get_overall_analysis_status(),
            "status_counts": self.analysis_status_counts,
        }
        summary: Dict[str, Any] = {
            "files_discovered": self.files_discovered or (self.scanned_files_count + len(self.ignored_paths) + len(self.failed_paths)),
            "files_analyzed": self.files_analyzed or self.scanned_files_count,
            "files_ignored": self.files_ignored or len(self.ignored_paths),
            "files_failed": self.files_failed or len(self.failed_paths),
            "scanned_files_count": self.scanned_files_count,
            "total_lines_of_code": self.total_lines_of_code,
            "total_issues_count": self.total_issues_count,
            "high_severity_count": self.high_severity_count,
            "medium_severity_count": self.medium_severity_count,
            "low_severity_count": self.low_severity_count,
            "rules_applied_count": self.rules_applied,
            "ignored_paths_count": len(self.ignored_paths),
            "failed_paths_count": len(self.failed_paths),
        }
        if self.is_baseline_filtered:
            summary["baseline"] = {
                "new_issues_count": self.baseline_new_count,
                "resolved_issues_count": self.baseline_resolved_count,
                "total_issues_before_baseline_filter": self.baseline_total_before_filter,
            }
        return {
            "meta": {
                "tool": "C-GULL",
                "version": __version__,
                "full_name": "C-GULL: Code Guardian for Unchecked Logic & Leaks",
                "timestamp": self.timestamp,
                "target_path": self.target_path,
                "scan_duration_seconds": round(self.scan_duration_seconds, 4),
            },
            "analysis": analysis,
            "summary": summary,
            "issues": [issue.to_dict() for issue in self.issues],
            "file_summaries": [fs.to_dict() for fs in self.file_summaries],
            "ignored_paths": self.ignored_paths,
            "failed_paths": self.failed_paths,
        }
