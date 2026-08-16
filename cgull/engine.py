"""
Core Scanning Engine for C-GULL Static Analyzer.
Orchestrates recursive file discovery, .cgullignore filtering,
regex scanning, AST parsing, and issue aggregation.
"""

import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Optional, Set, Dict, Tuple
from pathlib import Path

from .models import ScanResult, Issue, Severity, FileScanSummary, AnalysisEngine
from .ignore import CGullIgnoreFilter
from .ast_analyzer import CASTParser, CASTContext
from .rules import get_all_rules, BaseRule
from .utils import SuppressionMap, mask_string_and_char_literals


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
        custom_ignore_patterns: Optional[List[str]] = None,
        jobs: int = 1,
    ) -> ScanResult:
        """
        Recursively scans a directory or single file for security vulnerabilities.

        `jobs` controls parallelism across files: 1 (default) scans
        sequentially in-process; >1 scans files concurrently using a
        process pool, which matters once a codebase has more than a
        handful of files since each file's regex + AST passes are
        independent and CPU-bound.
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

        if jobs and jobs > 1 and len(files_to_scan) > 1:
            results = self._scan_files_parallel(files_to_scan, jobs)
        else:
            results = self._scan_files_sequential(files_to_scan)

        for file_path, file_issues, loc, duration_ms in results:
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

        # Keep report output stable/deterministic regardless of scan order
        # (matters once parallel scanning can complete files out of order).
        file_summaries.sort(key=lambda fs: fs.file_path)
        all_issues.sort(key=lambda i: (i.file_path, i.line_number, i.column_number, i.rule_id))

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

    def _scan_files_sequential(self, files_to_scan: List[str]):
        results = []
        for file_path in files_to_scan:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue
            file_issues, loc, duration_ms = self._scan_single_file_content(file_path, content)
            results.append((file_path, file_issues, loc, duration_ms))
        return results

    def _scan_files_parallel(self, files_to_scan: List[str], jobs: int):
        # Rule instances aren't guaranteed picklable/shareable across
        # processes, and re-instantiating the default rule set per worker
        # is cheap, so workers rebuild their own scanner from engine_mode
        # alone rather than trying to pickle self.
        results = []
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            futures = {
                pool.submit(_scan_file_worker, file_path, self.engine_mode): file_path
                for file_path in files_to_scan
            }
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    file_issues, loc, duration_ms = future.result()
                except Exception:
                    continue
                results.append((file_path, file_issues, loc, duration_ms))
        return results

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

    def _scan_single_file_content(self, file_path: str, content: str) -> Tuple[List[Issue], int, float]:
        return _scan_file_content(content, file_path, self.rules, self.engine_mode, self.ast_parser)


def _scan_file_content(
    content: str,
    file_path: str,
    rules: List[BaseRule],
    engine_mode: AnalysisEngine,
    ast_parser: Optional[CASTParser] = None,
) -> Tuple[List[Issue], int, float]:
    """
    Module-level scan implementation shared by in-process and
    worker-process scanning paths.

    Comment/string handling: raw source lines are used only for (a)
    computing line count, (b) parsing `cgull-ignore` suppression
    directives, and (c) restoring the exact original text into each
    reported Issue's code_snippet. All rule matching -- both regex and
    AST -- runs against a *comment-stripped* view of the source, so a
    banned function name mentioned only in a trailing or leading comment
    can never trigger a finding. Call-pattern regex rules additionally
    receive a string-literal-masked view (quotes preserved, contents
    replaced with 'x') via `masked_line_content`, so text like
    `"please don't use gets()"` inside a string literal doesn't either.
    """
    t0 = time.time()
    ast_parser = ast_parser or CASTParser()
    raw_lines = content.splitlines()
    loc = len(raw_lines)
    issues: List[Issue] = []
    seen_keys: Set[str] = set()

    suppressions = SuppressionMap.from_source(raw_lines)

    def add_issue_if_unique(issue: Issue):
        if suppressions.is_suppressed(issue.line_number, issue.rule_id):
            return
        key = f"{issue.rule_id}:{issue.line_number}:{issue.message}"
        if key not in seen_keys:
            seen_keys.add(key)
            # Restore the original (uncleaned) source line for display,
            # regardless of what internal cleaned/masked view the rule
            # matched against.
            if 0 < issue.line_number <= len(raw_lines):
                issue.code_snippet = raw_lines[issue.line_number - 1].strip()
            issues.append(issue)

    # A single AST parse (which internally strips comments once) covers
    # both the regex pass and the AST pass -- no need to strip/parse the
    # file twice, and no need to parse at all in pure REGEX mode.
    if engine_mode == AnalysisEngine.REGEX:
        clean_lines, clean_code = CASTParser.strip_only(content)
        ast_ctx = None
    else:
        ast_ctx = ast_parser.parse(content)
        clean_lines = ast_ctx.clean_source.splitlines()
        clean_code = ast_ctx.clean_source

    # 1. Regex Pass
    if engine_mode in (AnalysisEngine.REGEX, AnalysisEngine.HYBRID):
        masked_lines = [mask_string_and_char_literals(line) for line in clean_lines]
        for line_no, line in enumerate(clean_lines, 1):
            if not line.strip():
                continue
            masked_line = masked_lines[line_no - 1]
            for rule in rules:
                found = rule.scan_line(
                    file_path=file_path,
                    line_number=line_no,
                    line_content=line,
                    full_code=clean_code,
                    source_lines=clean_lines,
                    masked_line_content=masked_line,
                )
                for iss in found:
                    add_issue_if_unique(iss)

    # 2. AST Pass
    if engine_mode in (AnalysisEngine.AST, AnalysisEngine.HYBRID):
        if ast_ctx is None:
            ast_ctx = ast_parser.parse(content)
        for rule in rules:
            ast_found = rule.scan_ast(file_path=file_path, ast_ctx=ast_ctx)
            for iss in ast_found:
                add_issue_if_unique(iss)

    # Sort issues by line number
    issues.sort(key=lambda x: (x.line_number, x.column_number))
    duration_ms = (time.time() - t0) * 1000.0
    return issues, loc, duration_ms


def _scan_file_worker(file_path: str, engine_mode: AnalysisEngine) -> Tuple[List[Issue], int, float]:
    """
    Entry point run in a separate process by ProcessPoolExecutor. Rebuilds
    the default rule set locally (rule instances hold no per-scan state,
    so this is cheap) rather than pickling rule objects across the
    process boundary.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    rules = get_all_rules()
    return _scan_file_content(content, file_path, rules, engine_mode)
