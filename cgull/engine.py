"""
Core Scanning Engine for C-GULL Static Analyzer.
Orchestrates recursive file discovery, .cgullignore filtering,
regex scanning, AST parsing, and issue aggregation.
"""

import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Optional, Set, Dict, Tuple, Callable, Union, Any
from pathlib import Path

from .models import ScanResult, Issue, Severity, FileScanSummary, AnalysisEngine, ParserStatus, ParseTier, Confidence, ScanConfig, ScanError, ConfigProfile
from .ignore import CGullIgnoreFilter
from .ast_analyzer import CASTParser, CASTContext
from .rules import get_all_rules, BaseRule
from .utils import SuppressionMap, mask_string_and_char_literals, compute_issue_fingerprint, sanitize_terminal_text


def _emit_error(
    file_path: str,
    error_type: str,
    message: str,
    quiet: bool = False,
    progress_active: bool = False,
) -> None:
    if quiet:
        return
    san_path = sanitize_terminal_text(file_path)
    san_type = sanitize_terminal_text(error_type)
    san_msg = sanitize_terminal_text(message)
    prefix = "\n" if progress_active else ""
    sys.stderr.write(f"{prefix}[ERROR] Analysis failed for {san_path}: {san_type}: {san_msg}\n")
    sys.stderr.flush()


class CGullScanner:
    """
    Main static analyzer engine for C source code.
    """

    C_EXTENSIONS: Set[str] = {".c", ".h"}

    def __init__(
        self,
        rules: Optional[List[BaseRule]] = None,
        ignore_filter: Optional[CGullIgnoreFilter] = None,
        severity_filter: Optional[Set[Severity]] = None,
        engine_mode: AnalysisEngine = AnalysisEngine.HYBRID,
        defined_syms: Optional[Dict[str, Any]] = None,
        config: Optional[ScanConfig] = None,
    ):
        if config is not None:
            self.config = config
            if rules is not None or severity_filter is not None or engine_mode != AnalysisEngine.HYBRID or defined_syms is not None:
                self.config = ScanConfig.create(
                    rules=rules if rules is not None else self.config.get_rules(),
                    engine_mode=engine_mode if engine_mode != AnalysisEngine.HYBRID else self.config.engine_mode,
                    severity_filter=severity_filter if severity_filter is not None else self.config.severity_filter,
                    enable_inline_suppressions=self.config.enable_inline_suppressions,
                    suppression_config=self.config.suppression_config,
                    defined_syms=defined_syms if defined_syms is not None else self.config.defined_syms,
                )
        else:
            self.config = ScanConfig.create(
                rules=rules,
                engine_mode=engine_mode,
                severity_filter=severity_filter,
                defined_syms=defined_syms,
            )

        self.rules = self.config.get_rules()
        self.ignore_filter = ignore_filter
        self.severity_filter = self.config.severity_filter
        self.engine_mode = self.config.engine_mode
        self.ast_parser = CASTParser()

    def _get_active_config(self) -> ScanConfig:
        return ScanConfig.create(
            rules=self.rules,
            engine_mode=self.engine_mode,
            severity_filter=self.severity_filter,
            enable_inline_suppressions=self.config.enable_inline_suppressions,
            suppression_config=self.config.suppression_config,
            defined_syms=self.config.defined_syms,
        )

    def scan_path(
        self,
        target_path: str,
        ignore_file: Optional[str] = None,
        custom_ignore_patterns: Optional[List[str]] = None,
        jobs: int = 1,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        quiet: bool = False,
        profiles: Optional[List[ConfigProfile]] = None,
    ) -> ScanResult:
        """
        Recursively scans a directory or single file for security vulnerabilities.

        `jobs` controls parallelism across files:
        - 1 (default): sequential in-process scanning
        - N > 1: parallel scanning using N worker processes
        - 0: auto-detect and use all available CPU cores
        Negative values are invalid and raise a ValueError.
        """
        if jobs < 0:
            raise ValueError(f"Invalid jobs value: {jobs}. Must be non-negative (0 or greater).")

        resolved_jobs = (os.cpu_count() or 1) if jobs == 0 else jobs

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
                dirs[:] = [d for d in dirs if not self.ignore_filter.should_prune_dir(os.path.join(root, d))]
                for f in files:
                    file_path = os.path.join(root, f)
                    ext = os.path.splitext(f)[1].lower()
                    if ext in self.C_EXTENSIONS:
                        if self.ignore_filter.should_ignore(file_path):
                            ignored_paths.append(file_path)
                        else:
                            files_to_scan.append(file_path)

        total_files = len(files_to_scan)
        if total_files > 0:
            resolved_jobs = min(resolved_jobs, total_files)

        if progress_callback:
            progress_callback(0, total_files, "")

        config = self._get_active_config()
        self.config = config
        self.rules = config.get_rules()

        all_issues: List[Issue] = []
        file_summaries: List[FileScanSummary] = []
        failed_paths: List[str] = []
        scan_errors: List[ScanError] = []
        total_loc = 0
        analysis_status_counts: Dict[str, int] = {
            ParserStatus.PYCPARSER_SUCCESS.value: 0,
            ParserStatus.FALLBACK_PARSER.value: 0,
            ParserStatus.REGEX.value: 0,
            ParserStatus.PARSE_FAILED.value: 0,
        }

        progress_active = (progress_callback is not None) and (not quiet)
        if resolved_jobs > 1:
            results = self._scan_files_parallel(files_to_scan, resolved_jobs, config, progress_callback, quiet=quiet, progress_active=progress_active, profiles=profiles)
        else:
            results = self._scan_files_sequential(files_to_scan, config, progress_callback, quiet=quiet, progress_active=progress_active, profiles=profiles)

        analyzed_count = 0
        failed_count = 0

        for file_path, file_issues, loc, duration_ms, parser_status, parse_tier, file_status, file_confidence, scan_err in results:
            display_path = os.path.relpath(file_path, base_dir) if os.path.isdir(abs_target) else os.path.basename(file_path)

            analysis_status_counts[parser_status] = analysis_status_counts.get(parser_status, 0) + 1

            if file_status == "failed":
                failed_count += 1
                failed_paths.append(display_path)
                file_issues = []
                if scan_err:
                    scan_err.file_path = display_path
                    scan_errors.append(scan_err)
                else:
                    scan_errors.append(ScanError(
                        file_path=display_path,
                        error_type="UnknownError",
                        message="File analysis failed with unknown error",
                    ))
            else:
                analyzed_count += 1
                if self.severity_filter:
                    file_issues = [i for i in file_issues if i.impact in self.severity_filter]
                for issue in file_issues:
                    issue.file_path = display_path
                    issue.fingerprint = compute_issue_fingerprint(issue.rule_id, issue.file_path, issue.code_snippet)
                all_issues.extend(file_issues)

            total_loc += loc

            high_count = sum(1 for i in file_issues if i.impact == Severity.HIGH)
            med_count = sum(1 for i in file_issues if i.impact == Severity.MEDIUM)
            low_count = sum(1 for i in file_issues if i.impact == Severity.LOW)

            file_summaries.append(FileScanSummary(
                file_path=display_path,
                lines_of_code=loc,
                issues_count=len(file_issues),
                high_count=high_count,
                medium_count=med_count,
                low_count=low_count,
                scan_duration_ms=round(duration_ms, 2),
                parser=parser_status,
                status=file_status,
                confidence=file_confidence,
                parse_tier=parse_tier,
            ))

        duration = time.time() - start_time
        high_total = sum(1 for i in all_issues if i.impact == Severity.HIGH)
        med_total = sum(1 for i in all_issues if i.impact == Severity.MEDIUM)
        low_total = sum(1 for i in all_issues if i.impact == Severity.LOW)

        # Keep report output stable/deterministic regardless of scan order
        # (matters once parallel scanning can complete files out of order).
        file_summaries.sort(key=lambda fs: fs.file_path)
        all_issues.sort(key=lambda i: (i.file_path, i.line_number, i.column_number, i.rule_id, i.message))
        failed_paths.sort()
        scan_errors.sort(key=lambda e: (e.file_path, e.error_type, e.message))

        rel_ignored = [os.path.relpath(p, base_dir) if os.path.isdir(abs_target) else os.path.basename(p) for p in ignored_paths]
        rel_ignored.sort()
        files_discovered = len(files_to_scan) + len(ignored_paths)

        return ScanResult(
            target_path=target_path,
            scanned_files_count=analyzed_count,
            total_lines_of_code=total_loc,
            total_issues_count=len(all_issues),
            high_severity_count=high_total,
            medium_severity_count=med_total,
            low_severity_count=low_total,
            scan_duration_seconds=duration,
            timestamp=datetime.now(timezone.utc).isoformat(),
            issues=all_issues,
            file_summaries=file_summaries,
            scan_errors=scan_errors,
            ignored_paths=rel_ignored,
            failed_paths=failed_paths,
            files_discovered=files_discovered,
            files_analyzed=analyzed_count,
            files_ignored=len(rel_ignored),
            files_failed=failed_count,
            analysis_status_counts=analysis_status_counts,
            rules_applied=len(self.rules),
        )

    def _scan_files_sequential(
        self,
        files_to_scan: List[str],
        config: ScanConfig,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        quiet: bool = False,
        progress_active: bool = False,
        profiles: Optional[List[ConfigProfile]] = None,
    ):
        results = []
        total_files = len(files_to_scan)
        for idx, file_path in enumerate(files_to_scan, 1):
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err = self._scan_single_file_content(file_path, content, config=config, profiles=profiles, quiet=quiet, progress_active=progress_active)
                results.append((file_path, file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err))
            except Exception as e:
                scan_err = ScanError(
                    file_path=file_path,
                    error_type=type(e).__name__,
                    message=str(e) or f"Failed to read file: {file_path}",
                )
                _emit_error(file_path, scan_err.error_type, scan_err.message, quiet=quiet, progress_active=progress_active)
                results.append((file_path, [], 0, 0.0, ParserStatus.PARSE_FAILED.value, ParseTier.REGEX_FALLBACK.value, "failed", Confidence.LIMITED.value, scan_err))
            if progress_callback:
                progress_callback(idx, total_files, file_path)
        return results

    def _scan_files_parallel(
        self,
        files_to_scan: List[str],
        jobs: int,
        config: ScanConfig,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        quiet: bool = False,
        progress_active: bool = False,
        profiles: Optional[List[ConfigProfile]] = None,
    ):
        import pickle
        try:
            pickle.dumps(config)
            if profiles:
                pickle.dumps(profiles)
        except Exception as e:
            raise ValueError(
                f"Configuration/profiles cannot be serialized for parallel worker processes: {e}. "
                f"Ensure all custom rules and profiles are picklable or use jobs=1 for sequential scanning."
            ) from e

        results = []
        total_files = len(files_to_scan)
        completed_count = 0
        pool = ProcessPoolExecutor(max_workers=jobs)
        try:
            futures = {
                pool.submit(_scan_file_worker, file_path, config, profiles, quiet, progress_active): file_path
                for file_path in files_to_scan
            }
            for future in as_completed(futures):
                file_path = futures[future]
                completed_count += 1
                try:
                    file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err = future.result()
                    results.append((file_path, file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err))
                except Exception as e:
                    scan_err = ScanError(
                        file_path=file_path,
                        error_type=type(e).__name__,
                        message=str(e) or f"Worker execution failed for {file_path}",
                    )
                    _emit_error(file_path, scan_err.error_type, scan_err.message, quiet=quiet, progress_active=progress_active)
                    results.append((file_path, [], 0, 0.0, ParserStatus.PARSE_FAILED.value, ParseTier.REGEX_FALLBACK.value, "failed", Confidence.LIMITED.value, scan_err))
                if progress_callback:
                    progress_callback(completed_count, total_files, file_path)
            pool.shutdown(wait=True)
        except BaseException:
            procs = list((getattr(pool, "_processes", {}) or {}).values())
            pool.shutdown(wait=False, cancel_futures=True)
            for p in procs:
                if p and p.is_alive():
                    p.terminate()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        return results

    def scan_text(self, source_code: str, file_path: str = "source.c", quiet: bool = False, profiles: Optional[List[ConfigProfile]] = None) -> ScanResult:
        """
        Directly scans in-memory C source text.
        """
        start_time = time.time()
        config = self._get_active_config()
        self.config = config
        self.rules = config.get_rules()

        file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err = self._scan_single_file_content(file_path, source_code, config=config, profiles=profiles, quiet=quiet)
        scan_errors = []
        if status == "failed":
            if scan_err:
                scan_errors.append(scan_err)
            else:
                scan_errors.append(ScanError(
                    file_path=file_path,
                    error_type="UnknownError",
                    message="File analysis failed with unknown error",
                ))

        for issue in file_issues:
            issue.fingerprint = compute_issue_fingerprint(issue.rule_id, issue.file_path, issue.code_snippet)

        if self.severity_filter:
            file_issues = [i for i in file_issues if i.impact in self.severity_filter]

        duration = time.time() - start_time
        high_total = sum(1 for i in file_issues if i.impact == Severity.HIGH)
        med_total = sum(1 for i in file_issues if i.impact == Severity.MEDIUM)
        low_total = sum(1 for i in file_issues if i.impact == Severity.LOW)

        return ScanResult(
            target_path=file_path,
            scanned_files_count=1 if status != "failed" else 0,
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
                parser=parser_status,
                status=status,
                confidence=confidence,
                parse_tier=parse_tier,
            )],
            scan_errors=scan_errors,
            ignored_paths=[],
            failed_paths=[file_path] if status == "failed" else [],
            files_discovered=1,
            files_analyzed=1 if status != "failed" else 0,
            files_ignored=0,
            files_failed=1 if status == "failed" else 0,
            analysis_status_counts={parser_status: 1},
            rules_applied=len(self.rules),
        )

    def scan_profiles(
        self,
        target_path: str,
        profiles: List[ConfigProfile],
        ignore_file: Optional[str] = None,
        custom_ignore_patterns: Optional[List[str]] = None,
        jobs: int = 1,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        quiet: bool = False,
    ) -> ScanResult:
        """
        Scans a target directory or file across a list of ConfigProfiles,
        resolving preprocessor conditionals per config and merging findings
        with reachable_under tags.
        """
        return self.scan_path(
            target_path=target_path,
            profiles=profiles,
            ignore_file=ignore_file,
            custom_ignore_patterns=custom_ignore_patterns,
            jobs=jobs,
            progress_callback=progress_callback,
            quiet=quiet,
        )

    def scan_text_profiles(
        self,
        source_code: str,
        profiles: List[ConfigProfile],
        file_path: str = "source.c",
        quiet: bool = False,
    ) -> ScanResult:
        """
        Scans in-memory C source text across a list of ConfigProfiles,
        resolving preprocessor conditionals per config and merging findings
        with reachable_under tags.
        """
        return self.scan_text(
            source_code=source_code,
            file_path=file_path,
            profiles=profiles,
            quiet=quiet,
        )

    def _scan_single_file_content(
        self,
        file_path: str,
        content: str,
        config: Optional[ScanConfig] = None,
        profiles: Optional[List[ConfigProfile]] = None,
        quiet: bool = False,
        progress_active: bool = False,
    ) -> Tuple[List[Issue], int, float, str, str, str, str, Optional[ScanError]]:
        if config is None:
            config = self._get_active_config()
        return _scan_file_content_profiles(content, file_path, profiles=profiles, ast_parser=self.ast_parser, config=config, quiet=quiet, progress_active=progress_active)


def _scan_file_content(
    content: str,
    file_path: str,
    rules: Optional[List[BaseRule]] = None,
    engine_mode: Optional[AnalysisEngine] = None,
    ast_parser: Optional[CASTParser] = None,
    config: Optional[ScanConfig] = None,
    quiet: bool = False,
    progress_active: bool = False,
) -> Tuple[List[Issue], int, float, str, str, str, str, Optional[ScanError]]:
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
    if config is not None:
        rules = config.get_rules()
        engine_mode = config.engine_mode
        sev_filter = config.severity_filter
        enable_suppressions = config.enable_inline_suppressions
    else:
        rules = rules if rules is not None else get_all_rules()
        engine_mode = engine_mode if engine_mode is not None else AnalysisEngine.HYBRID
        sev_filter = None
        enable_suppressions = True

    t0 = time.time()
    ast_parser = ast_parser or CASTParser()
    raw_lines = content.splitlines()
    loc = len(raw_lines)
    issues: List[Issue] = []
    seen_keys: Set[str] = set()

    suppressions = SuppressionMap.from_source(raw_lines) if enable_suppressions else None

    def add_issue_if_unique(issue: Issue):
        if suppressions and suppressions.is_suppressed(issue.line_number, issue.rule_id):
            return
        if sev_filter and issue.impact not in sev_filter:
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

    parser_status = ParserStatus.FALLBACK_PARSER.value
    parse_tier = ParseTier.REGEX_FALLBACK.value
    file_status = "success"
    confidence_val = Confidence.FALLBACK.value
    scan_error: Optional[ScanError] = None

    try:
        # A single AST parse (which internally strips comments once) covers
        # both the regex pass and the AST pass -- no need to strip/parse the
        # file twice, and no need to parse at all in pure REGEX mode.
        if engine_mode == AnalysisEngine.REGEX:
            clean_lines, clean_code = CASTParser.strip_only(content)
            from .ast_analyzer import resolve_preprocessor_conditionals
            clean_code = resolve_preprocessor_conditionals(clean_code, defined_syms=config.defined_syms if config else None)
            clean_lines = clean_code.splitlines()
            ast_ctx = None
            parser_status = ParserStatus.REGEX.value
            parse_tier = ParseTier.REGEX_FALLBACK.value
            confidence_val = Confidence.LIMITED.value
        else:
            ast_ctx = ast_parser.parse(content, defined_syms=config.defined_syms if config else None)
            clean_lines = ast_ctx.clean_source.splitlines()
            clean_code = ast_ctx.clean_source
            parser_status = ast_ctx.parser_status
            parse_tier = ast_ctx.parse_tier
            confidence_val = Confidence.FULL.value if parser_status == ParserStatus.PYCPARSER_SUCCESS.value else Confidence.FALLBACK.value

        # 1. Regex Pass
        if engine_mode in (AnalysisEngine.REGEX, AnalysisEngine.HYBRID):
            masked_lines = [mask_string_and_char_literals(line) for line in clean_lines]
            for line_no, line in enumerate(clean_lines, 1):
                if not line.strip():
                    continue
                masked_line = masked_lines[line_no - 1]
                for rule in rules:
                    if engine_mode == AnalysisEngine.HYBRID and rule.analysis_engine == AnalysisEngine.AST:
                        continue
                    found = rule.scan_line(
                        file_path=file_path,
                        line_number=line_no,
                        line_content=line,
                        full_code=clean_code,
                        source_lines=clean_lines,
                        masked_line_content=masked_line,
                    )
                    for iss in found:
                        if iss.confidence is None:
                            iss.confidence = Confidence(confidence_val)
                        add_issue_if_unique(iss)

        # 2. AST Pass
        if engine_mode in (AnalysisEngine.AST, AnalysisEngine.HYBRID):
            if ast_ctx is None:
                ast_ctx = ast_parser.parse(content)
                parser_status = ast_ctx.parser_status
                confidence_val = Confidence.FULL.value if parser_status == ParserStatus.PYCPARSER_SUCCESS.value else Confidence.FALLBACK.value
            for rule in rules:
                ast_found = rule.scan_ast(file_path=file_path, ast_ctx=ast_ctx)
                for iss in ast_found:
                    if iss.confidence is None:
                        iss.confidence = Confidence(confidence_val)
                    add_issue_if_unique(iss)

    except Exception as e:
        issues = []
        parser_status = ParserStatus.PARSE_FAILED.value
        parse_tier = ParseTier.REGEX_FALLBACK.value
        file_status = "failed"
        confidence_val = Confidence.LIMITED.value
        scan_error = ScanError(
            file_path=file_path,
            error_type=type(e).__name__,
            message=str(e) or "File analysis failed",
        )
        _emit_error(file_path, scan_error.error_type, scan_error.message, quiet=quiet, progress_active=progress_active)

    # Sort issues by line number
    issues.sort(key=lambda x: (x.line_number, x.column_number))
    duration_ms = (time.time() - t0) * 1000.0
    return issues, loc, duration_ms, parser_status, parse_tier, file_status, confidence_val, scan_error


def _scan_file_content_profiles(
    content: str,
    file_path: str,
    profiles: Optional[List[ConfigProfile]] = None,
    rules: Optional[List[BaseRule]] = None,
    engine_mode: Optional[AnalysisEngine] = None,
    ast_parser: Optional[CASTParser] = None,
    config: Optional[ScanConfig] = None,
    quiet: bool = False,
    progress_active: bool = False,
) -> Tuple[List[Issue], int, float, str, str, str, str, Optional[ScanError]]:
    if not profiles:
        return _scan_file_content(
            content=content,
            file_path=file_path,
            rules=rules,
            engine_mode=engine_mode,
            ast_parser=ast_parser,
            config=config,
            quiet=quiet,
            progress_active=progress_active,
        )

    if config is not None:
        base_rules = config.get_rules()
        base_engine_mode = config.engine_mode
        base_sev_filter = config.severity_filter
        base_enable_suppressions = config.enable_inline_suppressions
        base_suppression_config = config.suppression_config
    else:
        base_rules = rules if rules is not None else get_all_rules()
        base_engine_mode = engine_mode if engine_mode is not None else AnalysisEngine.HYBRID
        base_sev_filter = None
        base_enable_suppressions = True
        base_suppression_config = {}

    total_duration_ms = 0.0
    merged_issues: Dict[Tuple[str, int, str], Tuple[Issue, Set[ConfigProfile]]] = {}
    loc = len(content.splitlines())

    best_parser_status = ParserStatus.PARSE_FAILED.value
    best_parse_tier = ParseTier.REGEX_FALLBACK.value
    best_file_status = "failed"
    best_confidence = Confidence.LIMITED.value
    first_scan_err: Optional[ScanError] = None

    for cp in profiles:
        variant_config = ScanConfig.create(
            rules=base_rules,
            engine_mode=base_engine_mode,
            severity_filter=base_sev_filter,
            enable_inline_suppressions=base_enable_suppressions,
            suppression_config=base_suppression_config,
            defined_syms=cp.flags,
        )

        v_issues, v_loc, v_dur, v_parser_status, v_parse_tier, v_status, v_confidence, v_err = _scan_file_content(
            content=content,
            file_path=file_path,
            ast_parser=ast_parser,
            config=variant_config,
            quiet=quiet,
            progress_active=progress_active,
        )

        total_duration_ms += v_dur
        loc = max(loc, v_loc)

        if v_err and first_scan_err is None:
            first_scan_err = v_err

        if v_status == "success":
            best_file_status = "success"

        if v_parser_status == ParserStatus.PYCPARSER_SUCCESS.value:
            best_parser_status = ParserStatus.PYCPARSER_SUCCESS.value
            best_confidence = Confidence.FULL.value
        elif best_parser_status != ParserStatus.PYCPARSER_SUCCESS.value and v_parser_status == ParserStatus.FALLBACK_PARSER.value:
            best_parser_status = ParserStatus.FALLBACK_PARSER.value
            best_confidence = Confidence.FALLBACK.value
        elif best_parser_status not in (ParserStatus.PYCPARSER_SUCCESS.value, ParserStatus.FALLBACK_PARSER.value):
            best_parser_status = v_parser_status
            best_confidence = v_confidence

        if v_parse_tier == ParseTier.PCPP_PYCPARSER.value:
            best_parse_tier = ParseTier.PCPP_PYCPARSER.value
        elif best_parse_tier != ParseTier.PCPP_PYCPARSER.value and v_parse_tier == ParseTier.DIRECTIVE_STRIPPED.value:
            best_parse_tier = ParseTier.DIRECTIVE_STRIPPED.value

        for iss in v_issues:
            if not iss.fingerprint:
                iss.fingerprint = compute_issue_fingerprint(iss.rule_id, file_path, iss.code_snippet)
            key = (iss.fingerprint, iss.line_number, iss.message)
            if key not in merged_issues:
                merged_issues[key] = (iss, {cp})
            else:
                merged_issues[key][1].add(cp)

    num_profiles = len(profiles)
    final_issues: List[Issue] = []

    for key, (iss, seen_profs) in merged_issues.items():
        if len(seen_profs) == num_profiles:
            iss.reachable_under = ["unconditional"]
        else:
            iss.reachable_under = sorted({p.reachable_under for p in seen_profs if p.reachable_under})
        final_issues.append(iss)

    final_issues.sort(key=lambda x: (x.line_number, x.column_number, x.rule_id, x.message))

    return final_issues, loc, total_duration_ms, best_parser_status, best_parse_tier, best_file_status, best_confidence, first_scan_err


def _scan_file_worker(
    file_path: str,
    config: Union[ScanConfig, AnalysisEngine],
    profiles: Optional[List[ConfigProfile]] = None,
    quiet: bool = False,
    progress_active: bool = False,
) -> Tuple[List[Issue], int, float, str, str, str, str, Optional[ScanError]]:
    """
    Entry point run in a separate process by ProcessPoolExecutor. Rebuilds
    the rules and configuration from the provided ScanConfig.
    """
    if isinstance(config, AnalysisEngine):
        config = ScanConfig.create(engine_mode=config)
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        scan_err = ScanError(
            file_path=file_path,
            error_type=type(e).__name__,
            message=str(e) or f"Failed to read file: {file_path}",
        )
        _emit_error(file_path, scan_err.error_type, scan_err.message, quiet=quiet, progress_active=progress_active)
        return [], 0, 0.0, ParserStatus.PARSE_FAILED.value, ParseTier.REGEX_FALLBACK.value, "failed", Confidence.LIMITED.value, scan_err
    return _scan_file_content_profiles(content, file_path, profiles=profiles, config=config, quiet=quiet, progress_active=progress_active)
