"""
Core Scanning Engine for C-GULL Static Analyzer.
Orchestrates recursive file discovery, .cgullignore filtering,
regex scanning, AST parsing, and issue aggregation.
"""

import os
import time
from datetime import datetime, timezone
from typing import List, Optional, Set, Dict
from pathlib import Path

from .models import ScanResult, Issue, Severity, FileScanSummary, AnalysisEngine
from .ignore import CGullIgnoreFilter
from .ast_analyzer import CASTParser, CASTContext
from .rules import get_all_rules, BaseRule


class CGullScanner:
    """
    Main static analyzer engine for C source code.
    """

    C_EXTENSIONS: Set[str] = {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"}

    def __init__(
        self,
        rules: Optional[List[BaseRule]] = None,
        ignore_filter: Optional[CGullIgnoreFilter] = None,
        severity_filter: Optional[Set[Severity]] = None,
        engine_mode: AnalysisEngine = AnalysisEngine.HYBRID,
    ):
        self.rules = rules if rules is not None else get_all_rules()
        self.ignore_filter = ignore_filter
        self.severity_filter = severity_filter
        self.engine_mode = engine_mode
        self.ast_parser = CASTParser()

    def scan_path(
        self,
        target_path: str,
        ignore_file: Optional[str] = None,
        custom_ignore_patterns: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Recursively scans a directory or single file for security vulnerabilities.
        """
        start_time = time.time()
        abs_target = os.path.abspath(target_path)

        # Set up ignore filter
        base_dir = abs_target if os.path.isdir(abs_target) else os.path.dirname(abs_target)
        if self.ignore_filter is None:
            self.ignore_filter = CGullIgnoreFilter(base_dir=base_dir, custom_patterns=custom_ignore_patterns)
        if ignore_file and os.path.exists(ignore_file):
            self.ignore_filter.load_from_file(ignore_file)

        files_to_scan: List[str] = []
        ignored_paths: List[str] = []

        if os.path.isfile(abs_target):
            if self.ignore_filter.should_ignore(abs_target):
                ignored_paths.append(abs_target)
            else:
                files_to_scan.append(abs_target)
        elif os.path.isdir(abs_target):
            for root, dirs, files in os.walk(abs_target):
                # Filter directories in-place to prune walk
                dirs_to_keep = []
                for d in dirs:
                    dir_path = os.path.join(root, d)
                    if self.ignore_filter.should_ignore(dir_path, is_dir=True):
                        ignored_paths.append(dir_path)
                    else:
                        dirs_to_keep.append(d)
                dirs[:] = dirs_to_keep

                for f in files:
                    file_path = os.path.join(root, f)
                    ext = os.path.splitext(f)[1].lower()
                    if ext in self.C_EXTENSIONS:
                        if self.ignore_filter.should_ignore(file_path):
                            ignored_paths.append(file_path)
                        else:
                            files_to_scan.append(file_path)

        all_issues: List[Issue] = []
        file_summaries: List[FileScanSummary] = []
        total_loc = 0

        for file_path in files_to_scan:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as e:
                continue

            file_issues, loc, duration_ms = self._scan_single_file_content(file_path, content)
            total_loc += loc
            all_issues.extend(file_issues)

            high_count = sum(1 for i in file_issues if i.impact == Severity.HIGH)
            med_count = sum(1 for i in file_issues if i.impact == Severity.MEDIUM)
            low_count = sum(1 for i in file_issues if i.impact == Severity.LOW)

            file_summaries.append(FileScanSummary(
                file_path=os.path.relpath(file_path, base_dir) if os.path.isdir(abs_target) else os.path.basename(file_path),
                lines_of_code=loc,
                issues_count=len(file_issues),
                high_count=high_count,
                medium_count=med_count,
                low_count=low_count,
                scan_duration_ms=round(duration_ms, 2)
            ))

        # Filter by severity if specified
        if self.severity_filter:
            all_issues = [i for i in all_issues if i.impact in self.severity_filter]

        duration = time.time() - start_time
        high_total = sum(1 for i in all_issues if i.impact == Severity.HIGH)
        med_total = sum(1 for i in all_issues if i.impact == Severity.MEDIUM)
        low_total = sum(1 for i in all_issues if i.impact == Severity.LOW)

        return ScanResult(
            target_path=target_path,
            scanned_files_count=len(files_to_scan),
            total_lines_of_code=total_loc,
            total_issues_count=len(all_issues),
            high_severity_count=high_total,
            medium_severity_count=med_total,
            low_severity_count=low_total,
            scan_duration_seconds=duration,
            timestamp=datetime.now(timezone.utc).isoformat(),
            issues=all_issues,
            file_summaries=file_summaries,
            ignored_paths=[os.path.relpath(p, base_dir) for p in ignored_paths],
            rules_applied=len(self.rules),
        )

    def scan_text(self, source_code: str, file_path: str = "source.c") -> ScanResult:
        """
        Directly scans in-memory C source text.
        """
        start_time = time.time()
        file_issues, loc, duration_ms = self._scan_single_file_content(file_path, source_code)

        if self.severity_filter:
            file_issues = [i for i in file_issues if i.impact in self.severity_filter]

        duration = time.time() - start_time
        high_total = sum(1 for i in file_issues if i.impact == Severity.HIGH)
        med_total = sum(1 for i in file_issues if i.impact == Severity.MEDIUM)
        low_total = sum(1 for i in file_issues if i.impact == Severity.LOW)

        return ScanResult(
            target_path=file_path,
            scanned_files_count=1,
            total_lines_of_code=loc,
            total_issues_count=len(file_issues),
            high_severity_count=high_total,
            medium_severity_count=med_total,
            low_severity_count=low_total,
            scan_duration_seconds=duration,
            timestamp=datetime.now(timezone.utc).isoformat(),
            issues=file_issues,
            file_summaries=[FileScanSummary(
                file_path=file_path,
                lines_of_code=loc,
                issues_count=len(file_issues),
                high_count=high_total,
                medium_count=med_total,
                low_count=low_total,
                scan_duration_ms=round(duration_ms, 2),
            )],
            ignored_paths=[],
            rules_applied=len(self.rules),
        )

    def _scan_single_file_content(self, file_path: str, content: str) -> (List[Issue], int, float):
        t0 = time.time()
        lines = content.splitlines()
        loc = len(lines)
        issues: List[Issue] = []
        seen_keys: Set[str] = set()

        def add_issue_if_unique(issue: Issue):
            key = f"{issue.rule_id}:{issue.line_number}:{issue.message}"
            if key not in seen_keys:
                seen_keys.add(key)
                issues.append(issue)

        # 1. Regex Pass
        if self.engine_mode in (AnalysisEngine.REGEX, AnalysisEngine.HYBRID):
            for line_no, line in enumerate(lines, 1):
                # Skip pure comments for line checks
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    continue

                for rule in self.rules:
                    found = rule.scan_line(
                        file_path=file_path,
                        line_number=line_no,
                        line_content=line,
                        full_code=content,
                        source_lines=lines,
                    )
                    for iss in found:
                        add_issue_if_unique(iss)

        # 2. AST Pass
        if self.engine_mode in (AnalysisEngine.AST, AnalysisEngine.HYBRID):
            ast_ctx = self.ast_parser.parse(content)
            for rule in self.rules:
                ast_found = rule.scan_ast(file_path=file_path, ast_ctx=ast_ctx)
                for iss in ast_found:
                    add_issue_if_unique(iss)

        # Sort issues by line number
        issues.sort(key=lambda x: (x.line_number, x.column_number))
        duration_ms = (time.time() - t0) * 1000.0
        return issues, loc, duration_ms
