"""
C-GULL: Code Guardian for Unchecked Logic & Leaks
A lightweight & AST-capable C Static Code Security Analyzer.
"""

__version__ = "0.6.8"
__author__ = "Saheb Biswas"

from .models import Issue, Severity, ScanResult, RuleDefinition, AnalysisEngine, FixType, ScanConfig, ScanError
from .engine import CGullScanner
from .ignore import CGullIgnoreFilter
from .reporter import ReportGenerator

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
]
