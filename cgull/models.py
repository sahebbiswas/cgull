"""
Data models for C-GULL Static Analyzer.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
import types
from typing import List, Dict, Any, Optional, Set, Union, Mapping
import time
import logging
from . import __version__

logger = logging.getLogger(__name__)


OUTPUT_SCHEMA_VERSION = "1"


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ScanMode(str, Enum):
    FILE = "file"
    TU = "tu"


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
    REGEX = "regex"
    PARSE_FAILED = "parse-failed"


class ParseTier(str, Enum):
    PCPP_PYCPARSER = "pcpp+pycparser"
    DIRECTIVE_STRIPPED = "directive-stripped"
    REGEX_FALLBACK = "regex-fallback"


class Confidence(str, Enum):
    FULL = "FULL"
    FALLBACK = "FALLBACK"
    LIMITED = "LIMITED"


@dataclass(frozen=True, eq=False)
class ConfigProfile:
    """
    Internal flag-map schema representing a single build/scan configuration profile.

    Attributes:
        name: Name of the configuration profile (e.g., "debug").
        flags: Flag map mapping macro names to values or None.
            None represents a presence toggle (#ifdef / bare #define),
            while str/int/etc. represent value macros (#define RETRY_COUNT 5).
    """
    name: str
    flags: Mapping[str, Optional[Union[str, int]]] = field(default_factory=dict)

    def __post_init__(self):
        if self.flags is None:
            f_dict = {}
        else:
            f_dict = dict(self.flags)
        object.__setattr__(self, "flags", types.MappingProxyType(f_dict))

    @property
    def presence_flags(self) -> Set[str]:
        """
        Returns set of macro names configured as presence toggles (value is None, #ifdef style).
        """
        return {k for k, v in self.flags.items() if v is None}

    @property
    def value_flags(self) -> Dict[str, Union[str, int]]:
        """
        Returns dict of macro names to values for value macros (value is not None, e.g. #define RETRY 5).
        """
        return {k: v for k, v in self.flags.items() if v is not None}

    @property
    def label(self) -> str:
        """
        Returns the reachable_under label representation of the configuration.
        e.g., "debug" -> "+debug", "+release" -> "+release", "" -> "+default".
        """
        name_str = self.name.strip() if self.name else ""
        if not name_str:
            name_str = "default"
        if name_str.startswith("+"):
            return name_str
        return f"+{name_str}"

    @property
    def reachable_under(self) -> str:
        """
        Alias for label (the reachable_under label).
        """
        return self.label

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ConfigProfile):
            return NotImplemented
        return self.name == other.name and frozenset(self.flags.items()) == frozenset(other.flags.items())

    def __hash__(self) -> int:
        return hash((self.name, frozenset(self.flags.items())))

    def __str__(self) -> str:
        return self.label

    def __repr__(self) -> str:
        return f"ConfigProfile(name={self.name!r}, flags={self.flags!r})"

    def __getstate__(self) -> Dict[str, Any]:
        return {"name": self.name, "flags": dict(self.flags)}

    def __setstate__(self, state: Dict[str, Any]) -> None:
        object.__setattr__(self, "name", state["name"])
        object.__setattr__(self, "flags", types.MappingProxyType(state["flags"]))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "flags": dict(self.flags),
            "presence_flags": sorted(self.presence_flags),
            "value_flags": dict(self.value_flags),
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConfigProfile":
        if "flags" in data:
            flags = dict(data["flags"])
        else:
            flags = {}
            for k in data.get("presence_flags", []):
                flags[k] = None
            for k, v in data.get("value_flags", {}).items():
                flags[k] = v

        return cls(
            name=data.get("name", ""),
            flags=flags,
        )


@dataclass
class ScanConfig:
    """
    Serializable configuration object encapsulating all options for a scan.
    Propagated to parallel workers to guarantee identical execution behavior
    and rule configuration between sequential (jobs=1) and parallel (jobs>1) scans.
    """
    rules: List[Any] = field(default_factory=list)
    engine_mode: AnalysisEngine = AnalysisEngine.HYBRID
    severity_filter: Optional[Set[Severity]] = None
    enable_inline_suppressions: bool = True
    suppression_config: Dict[str, Any] = field(default_factory=dict)
    defined_syms: Optional[Dict[str, Any]] = None
    config_strategy: str = "one-at-a-time"
    exhaustive_threshold: int = 10
    include_roots: List[str] = field(default_factory=list)
    dedup_headers: bool = True
    mode: ScanMode = ScanMode.FILE

    @classmethod
    def create(
        cls,
        rules: Optional[List[Any]] = None,
        engine_mode: AnalysisEngine = AnalysisEngine.HYBRID,
        severity_filter: Optional[Set[Severity]] = None,
        enable_inline_suppressions: bool = True,
        suppression_config: Optional[Dict[str, Any]] = None,
        defined_syms: Optional[Dict[str, Any]] = None,
        config_strategy: str = "one-at-a-time",
        exhaustive_threshold: int = 10,
        include_roots: Optional[List[str]] = None,
        dedup_headers: bool = True,
        mode: Union[ScanMode, str] = ScanMode.FILE,
    ) -> "ScanConfig":
        if isinstance(mode, str):
            mode = ScanMode(mode.lower())
        if rules is None:
            from .rules import get_all_rules
            rule_instances = get_all_rules()
        else:
            from .rules import BaseRule
            rule_instances = []
            for r in rules:
                rule_obj = r() if isinstance(r, type) and issubclass(r, BaseRule) else r
                rule_instances.append(rule_obj)

        return cls(
            rules=rule_instances,
            engine_mode=engine_mode,
            severity_filter=severity_filter,
            enable_inline_suppressions=enable_inline_suppressions,
            suppression_config=suppression_config or {},
            defined_syms=defined_syms,
            config_strategy=config_strategy,
            exhaustive_threshold=exhaustive_threshold,
            include_roots=list(include_roots) if include_roots is not None else [],
            dedup_headers=dedup_headers,
            mode=mode,
        )

    def get_rules(self) -> List[Any]:
        return self.rules

    def to_dict(self) -> Dict[str, Any]:
        from .rules import RULE_REGISTRY
        enabled_rule_ids = []
        for r in self.rules:
            rule_id = getattr(r, "rule_id", None)
            reg_cls = RULE_REGISTRY.get(rule_id) if rule_id else None
            if reg_cls is not None and type(r) is reg_cls:
                enabled_rule_ids.append(rule_id)
            else:
                raise ValueError(
                    f"Cannot serialize ScanConfig to dict because rule {r!r} (type {type(r).__name__}) "
                    "is a custom rule not registered in RULE_REGISTRY. Register custom rules using "
                    "cgull.rules.register_rule(rule_cls) before serializing configuration."
                )

        return {
            "enabled_rule_ids": enabled_rule_ids,
            "engine_mode": self.engine_mode.value if isinstance(self.engine_mode, AnalysisEngine) else str(self.engine_mode),
            "severity_filter": [s.value if isinstance(s, Severity) else str(s) for s in self.severity_filter] if self.severity_filter is not None else None,
            "enable_inline_suppressions": self.enable_inline_suppressions,
            "suppression_config": self.suppression_config,
            "defined_syms": self.defined_syms,
            "config_strategy": self.config_strategy,
            "exhaustive_threshold": self.exhaustive_threshold,
            "include_roots": list(self.include_roots),
            "dedup_headers": self.dedup_headers,
            "mode": self.mode.value if isinstance(self.mode, ScanMode) else str(self.mode),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanConfig":
        from .rules import get_rule_by_id
        engine_mode = AnalysisEngine(data.get("engine_mode", AnalysisEngine.HYBRID.value))
        sev_raw = data.get("severity_filter")
        severity_filter = {Severity(s) for s in sev_raw} if sev_raw is not None else None
        rule_ids = data.get("enabled_rule_ids", [])
        rules = [get_rule_by_id(rid) for rid in rule_ids]
        return cls(
            rules=rules,
            engine_mode=engine_mode,
            severity_filter=severity_filter,
            enable_inline_suppressions=data.get("enable_inline_suppressions", True),
            suppression_config=data.get("suppression_config", {}),
            defined_syms=data.get("defined_syms"),
            config_strategy=data.get("config_strategy", "one-at-a-time"),
            exhaustive_threshold=data.get("exhaustive_threshold", 10),
            include_roots=list(data.get("include_roots", [])),
            dedup_headers=data.get("dedup_headers", True),
            mode=ScanMode(data.get("mode", ScanMode.FILE.value)),
        )


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
    reachable_under: List[str] = field(default_factory=list)
    # List of translation units (files) that contributed this issue (for header deduplication)
    related_tus: List[str] = field(default_factory=list)

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
            "reachable_under": list(self.reachable_under),
            "related_tus": list(self.related_tus),
        }
        if conf_val:
            d["confidence"] = conf_val
        return d


@dataclass
class ScanError:
    file_path: str
    error_type: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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
    parse_tier: str = ParseTier.REGEX_FALLBACK.value

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
    scan_errors: List[ScanError] = field(default_factory=list)
    baseline_rules_count: Optional[int] = None

    def get_overall_parser_status(self) -> str:
        if self.overall_parser_status:
            return self.overall_parser_status
        pyc_count = self.analysis_status_counts.get(ParserStatus.PYCPARSER_SUCCESS.value, 0)
        fallback_count = self.analysis_status_counts.get(ParserStatus.FALLBACK_PARSER.value, 0)
        regex_count = self.analysis_status_counts.get(ParserStatus.REGEX.value, 0)
        failed_count = self.analysis_status_counts.get(ParserStatus.PARSE_FAILED.value, 0)

        if pyc_count > 0:
            if fallback_count > 0 or regex_count > 0:
                return "hybrid"
            return "pycparser"
        elif fallback_count > 0:
            return "fallback-parser"
        elif regex_count > 0:
            return "regex"
        elif failed_count > 0:
            return "parse-failed"
        return "none"

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
                "rules_applied_count": self.baseline_rules_count,
            }
        return {
            "schema_version": OUTPUT_SCHEMA_VERSION,
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
            "scan_errors": [err.to_dict() for err in self.scan_errors],
            "ignored_paths": self.ignored_paths,
            "failed_paths": self.failed_paths,
        }
