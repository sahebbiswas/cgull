"""
C-GULL: Code Guardian for Unchecked Logic & Leaks
A lightweight & AST-capable C Static Code Security Analyzer.
"""

__version__ = "0.9.32"
__author__ = "Saheb Biswas"

from .logging_config import configure_logging, TRACE_LEVEL_NUM
from .models import Issue, Severity, ScanResult, RuleDefinition, AnalysisEngine, FixType, ScanConfig, ScanError, ParseTier, ConfigProfile, ScanMode, OUTPUT_SCHEMA_VERSION
from .engine import CGullScanner
from .ignore import CGullIgnoreFilter
from .includes import IncludeResolver, TUIncludeExpander, expand_includes
from .reporter import ReportGenerator
from .config import CGullConfig, load_config
from .ast_analyzer import (
    ConditionalFlagCollector,
    CollectedFlags,
    FieldInfo,
    StructDef,
    generate_config_profiles,
    parse_config_seed,
    parse_config_seeds,
    parse_json_config_seed,
    parse_compile_commands,
    find_compile_commands,
    merge_profile_flags,
)

__all__ = [
    "CGullScanner",
    "CGullIgnoreFilter",
    "IncludeResolver",
    "TUIncludeExpander",
    "expand_includes",
    "ReportGenerator",
    "Issue",
    "Severity",
    "ScanResult",
    "RuleDefinition",
    "AnalysisEngine",
    "FixType",
    "ScanConfig",
    "ScanError",
    "ScanMode",
    "ParseTier",
    "ConfigProfile",
    "CGullConfig",
    "load_config",
    "OUTPUT_SCHEMA_VERSION",
    "ConditionalFlagCollector",
    "CollectedFlags",
    "FieldInfo",
    "StructDef",
    "generate_config_profiles",
    "parse_config_seed",
    "parse_config_seeds",
    "parse_json_config_seed",
    "parse_compile_commands",
    "find_compile_commands",
    "merge_profile_flags",
    "configure_logging",
    "TRACE_LEVEL_NUM",
]
