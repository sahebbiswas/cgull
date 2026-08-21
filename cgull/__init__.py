"""
C-GULL: Code Guardian for Unchecked Logic & Leaks
A lightweight & AST-capable C Static Code Security Analyzer.
"""

__version__ = "0.8.15"
__author__ = "Saheb Biswas"

from .models import Issue, Severity, ScanResult, RuleDefinition, AnalysisEngine, FixType, ScanConfig, ScanError, OUTPUT_SCHEMA_VERSION
from .engine import CGullScanner
from .ignore import CGullIgnoreFilter
from .reporter import ReportGenerator
from .config import CGullConfig, load_config

__all__ = [
    "CGullScanner",
    "CGullIgnoreFilter",
    "ReportGenerator",
    "Issue",
    "Severity",
    "ScanResult",
    "RuleDefinition",
    "AnalysisEngine",
    "FixType",
    "ScanConfig",
    "ScanError",
    "CGullConfig",
    "load_config",
    "OUTPUT_SCHEMA_VERSION",
]
