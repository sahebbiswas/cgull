"""
Data models for C-GULL Static Analyzer.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import time


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AnalysisEngine(str, Enum):
    REGEX = "Regex"
    AST = "AST"
    HYBRID = "Hybrid"


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

    def to_dict(self) -> Dict[str, Any]:
        return {
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
            "auto_fix_replacement": self.auto_fix_replacement,
        }


@dataclass
class FileScanSummary:
    file_path: str
    lines_of_code: int
    issues_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_duration_ms: float

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
    rules_applied: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "meta": {
                "tool": "C-GULL",
                "version": "0.4.0",
                "full_name": "C-GULL: Code Guardian for Unchecked Logic & Leaks",
                "timestamp": self.timestamp,
                "target_path": self.target_path,
                "scan_duration_seconds": round(self.scan_duration_seconds, 4),
            },
            "summary": {
                "scanned_files_count": self.scanned_files_count,
                "total_lines_of_code": self.total_lines_of_code,
                "total_issues_count": self.total_issues_count,
                "high_severity_count": self.high_severity_count,
                "medium_severity_count": self.medium_severity_count,
                "low_severity_count": self.low_severity_count,
                "rules_applied_count": self.rules_applied,
                "ignored_paths_count": len(self.ignored_paths),
            },
            "issues": [issue.to_dict() for issue in self.issues],
            "file_summaries": [fs.to_dict() for fs in self.file_summaries],
            "ignored_paths": self.ignored_paths,
        }
