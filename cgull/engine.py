"""
Core Scanning Engine for C-GULL Static Analyzer.
Orchestrates recursive file discovery, .cgullignore filtering,
regex scanning, AST parsing, and issue aggregation.
"""

import os
import sys
import time
import logging
import hashlib
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Optional, Set, Dict, Tuple, Callable, Union, Any
from pathlib import Path

from .logging_config import TRACE_LEVEL_NUM, multiprocessing_logging_context
from .parse_diagnostics import map_attempts, report_attempts, format_attempts
from .models import ScanResult, Issue, Severity, FileScanSummary, AnalysisEngine, ParserStatus, ParseTier, Confidence, FixType, ScanConfig, ScanError, ConfigProfile, ScanMode
from .ignore import CGullIgnoreFilter
from .includes import IncludeResolver, TUIncludeExpander, HEADER_CACHE
from .analysis_headers import is_analysis_header
from .ast_analyzer import CASTParser, CASTContext
from .rules import get_all_rules, BaseRule
from .utils import SuppressionMap, mask_string_and_char_literals, compute_issue_fingerprint, compute_issue_fingerprint_tu, sanitize_terminal_text

logger = logging.getLogger(__name__)


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
    logger.error("Analysis failed for %s: %s: %s", san_path, san_type, san_msg)


def _collect_files_flags(files: List[str], quiet: bool = False) -> Tuple[Set[str], Set[str], Dict[str, Tuple[str, int]], Dict[str, Tuple[str, int]]]:
    from .utils import strip_comments_keep_lines
    from .ast_analyzer import ConditionalFlagCollector

    presence_raw: Set[str] = set()
    value_raw: Set[str] = set()
    presence_locs: Dict[str, Tuple[str, int]] = {}
    value_locs: Dict[str, Tuple[str, int]] = {}
    skipped_error_count = 0

    for fpath in files:
        ext = os.path.splitext(fpath)[1].lower()
        if ext not in CGullScanner.C_EXTENSIONS:
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            _, clean_code = strip_comments_keep_lines(content)
            res = ConditionalFlagCollector.collect(clean_code, file_path=fpath)
            presence_raw.update(res.presence_flags)
            value_raw.update(res.value_flags)
            for k, v in res.presence_locations.items():
                if k not in presence_locs:
                    presence_locs[k] = v
            for k, v in res.value_locations.items():
                if k not in value_locs:
                    value_locs[k] = v
        except OSError as e:
            skipped_error_count += 1
            if not quiet:
                logger.warning("[WARNING] Flag collection skipped '%s' due to OS error: %s", fpath, e)
        except Exception as e:
            skipped_error_count += 1
            if not quiet:
                logger.warning("[WARNING] Flag collection skipped '%s' due to error: %s", fpath, e)

    if skipped_error_count > 0 and not quiet:
        logger.warning("Flag collection skipped %d file(s) due to errors", skipped_error_count)

    real_presence = presence_raw - value_raw
    return real_presence, value_raw, presence_locs, value_locs


def _collect_files_presence_flags(files: List[str], quiet: bool = False) -> Set[str]:
    presence, _, _, _ = _collect_files_flags(files, quiet=quiet)
    return presence


def _validate_seed_flags_diagnostics(files: List[str], seed_profiles: List[ConfigProfile], quiet: bool = False) -> None:
    if not seed_profiles or not files or quiet:
        return

    presence_flags, value_flags, presence_locs, value_locs = _collect_files_flags(files, quiet=quiet)
    all_discovered = presence_flags | value_flags

    # Collect all macros defined in seed profiles
    seed_macros: Dict[str, Set[str]] = {}  # macro -> set of profile names
    value_seed_macros: Dict[str, Tuple[Any, str]] = {}  # macro -> (value, profile_name)

    for p in seed_profiles:
        for m_name, val in p.flags.items():
            if m_name not in seed_macros:
                seed_macros[m_name] = set()
            seed_macros[m_name].add(p.name)
            if val is not None and not isinstance(val, bool):
                value_seed_macros[m_name] = (val, p.name)

    # Diagnostic 1: Unused macro warning (warn once per unused macro per run)
    for m_name in sorted(seed_macros.keys()):
        if m_name not in all_discovered:
            logger.warning("Warning: Seed macro '%s' is defined in configuration seed but never tested in any scanned source file.", m_name)

    # Diagnostic 2: Value-macro seed for a flag only tested as a presence flag (#ifdef)
    for m_name, (val, prof_name) in sorted(value_seed_macros.items()):
        if m_name in presence_flags and m_name not in value_flags:
            loc_str = ""
            if m_name in presence_locs:
                fpath, lno = presence_locs[m_name]
                loc_str = f" in {fpath}:{lno}"
            logger.warning("Warning: Seed value macro '%s' is configured with value '%s' but was only tested as a presence flag%s.", m_name, val, loc_str)


_CONFIDENCE_RANK = {
    Confidence.LIMITED: 0,
    Confidence.FALLBACK: 1,
    Confidence.FULL: 2,
}

_FIX_TYPE_RANK = {
    FixType.MANUAL_REVIEW: 0,
    FixType.SUGGESTED_FIX: 1,
    FixType.SAFE_FIX: 2,
}


def _confidence_rank(value: Any) -> int:
    try:
        return _CONFIDENCE_RANK[Confidence(value)]
    except (TypeError, ValueError, KeyError):
        return -1


def _fix_type_rank(value: Any) -> int:
    try:
        return _FIX_TYPE_RANK[FixType(value)]
    except (TypeError, ValueError, KeyError):
        return -1


def _issue_representative_key(issue: Issue) -> Tuple[Any, ...]:
    """Rank duplicate candidates without depending on discovery/worker order."""
    source_quality = (
        int(bool(issue.file_path))
        + int(issue.line_number > 0)
        + int(issue.column_number > 1)
        + int(bool(issue.code_snippet))
    )
    return (
        -source_quality,
        str(issue.file_path).replace("\\", "/"),
        issue.line_number,
        issue.column_number,
        issue.message,
        issue.engine,
        issue.code_snippet,
    )


def _merge_reachable_under(left: List[str], right: List[str]) -> List[str]:
    labels = {label for label in left + right if label}
    if "unconditional" in labels:
        return ["unconditional"]
    return sorted(labels)


def _merge_duplicate_issues(left: Issue, right: Issue) -> Issue:
    """Return one deterministic representative while preserving stronger metadata."""
    candidates = sorted((left, right), key=_issue_representative_key)
    representative = candidates[0]

    confidence_candidates = [issue.confidence for issue in candidates if issue.confidence is not None]
    if confidence_candidates:
        representative.confidence = max(
            confidence_candidates,
            key=lambda value: (_confidence_rank(value), str(value)),
        )

    fix_types = [issue.fix_type for issue in candidates]
    representative.fix_type = max(
        fix_types,
        key=lambda value: (_fix_type_rank(value), str(value)),
    )

    auto_fixes = sorted({
        issue.auto_fix_replacement
        for issue in candidates
        if issue.auto_fix_replacement
    })
    suggested_fixes = sorted({
        issue.suggested_fix_replacement
        for issue in candidates
        if issue.suggested_fix_replacement
    })
    representative.auto_fix_replacement = auto_fixes[0] if auto_fixes else None
    representative.suggested_fix_replacement = suggested_fixes[0] if suggested_fixes else None

    for attr in ("remediation", "cwe_id", "rule_name"):
        values = sorted({
            getattr(issue, attr)
            for issue in candidates
            if getattr(issue, attr)
        })
        if values:
            setattr(representative, attr, values[0])

    representative.related_tus = sorted({
        tu
        for issue in candidates
        for tu in issue.related_tus
        if tu
    })
    representative.reachable_under = _merge_reachable_under(
        left.reachable_under,
        right.reachable_under,
    )
    return representative


def _derived_occurrence_fingerprint(base_fingerprint: str, occurrence: int) -> str:
    """Disambiguate repeated physical occurrences without making line numbers identity."""
    if occurrence == 0:
        return base_fingerprint
    payload = f"{base_fingerprint}\0occurrence:{occurrence}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _merge_issue_cluster(cluster: List[Issue]) -> Issue:
    ordered = sorted(cluster, key=_issue_representative_key)
    merged = ordered[0]
    for candidate in ordered[1:]:
        merged = _merge_duplicate_issues(merged, candidate)
    return merged


def _coalesce_same_fingerprint_sites(candidates: List[Issue]) -> List[Issue]:
    """Merge analyzer variants at one site while preserving repeated source occurrences.

    The content fingerprint intentionally omits line numbers for baseline stability.
    It is therefore only a *base* identity until physical occurrences are separated.
    Precise columns distinguish multiple same-line findings; a coarse column (1)
    is merged into the sole precise site on that line when one exists, which covers
    AST-vs-regex variants of the same call without conflating separate calls.
    """
    by_line: Dict[int, List[Issue]] = {}
    for issue in candidates:
        by_line.setdefault(issue.line_number, []).append(issue)

    sites: List[Issue] = []
    for line_number in sorted(by_line):
        line_candidates = sorted(by_line[line_number], key=_issue_representative_key)
        precise: Dict[int, List[Issue]] = {}
        coarse: List[Issue] = []
        for issue in line_candidates:
            if issue.column_number > 1:
                precise.setdefault(issue.column_number, []).append(issue)
            else:
                coarse.append(issue)

        clusters: List[List[Issue]] = [
            precise[column]
            for column in sorted(precise)
        ]

        if len(clusters) == 1:
            clusters[0].extend(coarse)
        elif len(clusters) > 1:
            for issue in coarse:
                matching = [
                    cluster
                    for cluster in clusters
                    if any(candidate.message == issue.message for candidate in cluster)
                ]
                if len(matching) == 1:
                    matching[0].append(issue)
                else:
                    clusters.append([issue])
        elif coarse:
            engines = {issue.engine for issue in coarse}
            if len(engines) > 1 and all(
                sum(1 for candidate in coarse if candidate.engine == engine) == 1
                for engine in engines
            ):
                clusters = [coarse]
            else:
                clusters = [[issue] for issue in coarse]

        sites.extend(_merge_issue_cluster(cluster) for cluster in clusters)

    sites.sort(key=_issue_representative_key)
    return sites


def _deduplicate_issues_by_fingerprint(issues: List[Issue]) -> List[Issue]:
    """Finalize logical sites and ensure every normal-scan fingerprint is unique."""
    by_base_fingerprint: Dict[str, List[Issue]] = {}
    without_fingerprint: List[Issue] = []

    for issue in issues:
        if not issue.fingerprint:
            without_fingerprint.append(issue)
            continue
        by_base_fingerprint.setdefault(issue.fingerprint, []).append(issue)

    finalized: List[Issue] = []
    for base_fingerprint in sorted(by_base_fingerprint):
        sites = _coalesce_same_fingerprint_sites(by_base_fingerprint[base_fingerprint])
        for occurrence, issue in enumerate(sites):
            issue.fingerprint = _derived_occurrence_fingerprint(base_fingerprint, occurrence)
            finalized.append(issue)

    finalized.extend(without_fingerprint)
    finalized.sort(
        key=lambda issue: (
            issue.file_path,
            issue.line_number,
            issue.column_number,
            issue.rule_id,
            issue.message,
            issue.fingerprint,
        )
    )
    return finalized


class CGullScanner:
    """
    Main static analyzer engine for C source code.
    """

    C_EXTENSIONS: Set[str] = {".c", ".h", ".hpp"}

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
                    config_strategy=self.config.config_strategy,
                    exhaustive_threshold=self.config.exhaustive_threshold,
                    include_roots=self.config.include_roots,
                    include_root_warnings=self.config.include_root_warnings,
                    dedup_headers=getattr(self.config, "dedup_headers", True),
                    mode=getattr(self.config, "mode", ScanMode.FILE),
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
            config_strategy=self.config.config_strategy,
            exhaustive_threshold=self.config.exhaustive_threshold,
            include_roots=self.config.include_roots,
            dedup_headers=getattr(self.config, "dedup_headers", True),
            mode=getattr(self.config, "mode", ScanMode.FILE),
        )

    def scan_path(
        self,
        target_path: Union[str, List[str]],
        ignore_file: Optional[str] = None,
        custom_ignore_patterns: Optional[List[str]] = None,
        jobs: int = 1,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        quiet: bool = False,
        profiles: Optional[List[ConfigProfile]] = None,
        config_strategy: Optional[str] = None,
        exhaustive_threshold: Optional[int] = None,
        seed_profiles: Optional[List[ConfigProfile]] = None,
    ) -> ScanResult:
        """
        Recursively scans directories or files for security vulnerabilities.

        `jobs` controls parallelism across files:
        - 1 (default): sequential in-process scanning
        - N > 1: parallel scanning using N worker processes
        - 0: auto-detect and use all available CPU cores
        Negative values are invalid and raise a ValueError.
        """
        if jobs < 0:
            raise ValueError(f"Invalid jobs value: {jobs}. Must be non-negative (0 or greater).")

        resolved_jobs = (os.cpu_count() or 1) if jobs == 0 else jobs

        HEADER_CACHE.clear()
        start_time = time.time()

        if isinstance(target_path, (list, tuple)):
            raw_targets = list(target_path)
            report_target_str = " ".join(raw_targets) if len(raw_targets) > 1 else (raw_targets[0] if raw_targets else ".")
        else:
            raw_targets = [target_path]
            report_target_str = target_path

        abs_targets = [os.path.abspath(t) for t in raw_targets]

        # Determine base directory for relative display and ignore rules
        if len(abs_targets) == 1:
            base_dir = abs_targets[0] if os.path.isdir(abs_targets[0]) else (os.path.dirname(abs_targets[0]) or ".")
        else:
            try:
                common_p = os.path.commonpath(abs_targets)
                base_dir = common_p if os.path.isdir(common_p) else os.path.dirname(common_p)
            except ValueError:
                base_dir = os.getcwd()

        if self.ignore_filter is None:
            self.ignore_filter = CGullIgnoreFilter(base_dir=base_dir, custom_patterns=custom_ignore_patterns)
        if ignore_file and os.path.exists(ignore_file):
            self.ignore_filter.load_from_file(ignore_file)

        files_to_scan: List[str] = []
        ignored_paths: List[str] = []

        for abs_t in abs_targets:
            if is_analysis_header(abs_t):
                continue
            if os.path.isfile(abs_t):
                if self.ignore_filter.should_ignore(abs_t):
                    ignored_paths.append(abs_t)
                elif abs_t not in files_to_scan:
                    files_to_scan.append(abs_t)
            elif os.path.isdir(abs_t):
                for root, dirs, files in os.walk(abs_t):
                    dirs[:] = [d for d in dirs if not is_analysis_header(os.path.join(root, d))
                               and not self.ignore_filter.should_prune_dir(os.path.join(root, d))]
                    for f in files:
                        file_path = os.path.join(root, f)
                        ext = os.path.splitext(f)[1].lower()
                        if ext in self.C_EXTENSIONS and not is_analysis_header(file_path):
                            if self.ignore_filter.should_ignore(file_path):
                                if file_path not in ignored_paths:
                                    ignored_paths.append(file_path)
                            elif file_path not in files_to_scan:
                                files_to_scan.append(file_path)

        all_discovered_files = list(files_to_scan)

        if profiles is None and (config_strategy is not None or getattr(self.config, "config_strategy", "one-at-a-time") != "one-at-a-time"):
            strat = config_strategy if config_strategy is not None else getattr(self.config, "config_strategy", "one-at-a-time")
            ex_thresh = exhaustive_threshold if exhaustive_threshold is not None else getattr(self.config, "exhaustive_threshold", 10)
            target_presence_flags = _collect_files_presence_flags(all_discovered_files, quiet=quiet)
            if target_presence_flags or strat == "baseline":
                from .ast_analyzer import generate_config_profiles
                profiles = generate_config_profiles(
                    target_presence_flags,
                    strategy=strat,
                    exhaustive_threshold=ex_thresh,
                    base_flags=self.config.defined_syms,
                )

        prepared_source_units: Dict[str, Dict[Any, Any]] = {}
        source_preparation_diagnostics: Tuple[str, ...] = ()

        if self.config.mode == ScanMode.TU and files_to_scan:
            from .project_analysis import prepare_units, profile_key

            source_roots: List[str] = []
            headers: List[str] = []
            HEADER_EXTS = {".h", ".hpp"}
            for fpath in all_discovered_files:
                ext = os.path.splitext(fpath)[1].lower()
                if ext in HEADER_EXTS:
                    headers.append(fpath)
                else:
                    source_roots.append(fpath)

            preparation_config = self._get_active_config()
            active_profiles = profiles if profiles else seed_profiles
            prepared_source_units, source_preparation_diagnostics = prepare_units(
                source_roots,
                lambda path: self._config_for_file(preparation_config, path),
                active_profiles,
                jobs=resolved_jobs,
            )

            # Seed profiles are used for header reachability, while the actual
            # scan still uses their merged flags when no explicit/generated
            # profile set exists. Prepare that scan identity too so a one-root
            # directory does not fall back to a second include expansion.
            if profiles is None and seed_profiles:
                prepared_source_units, scan_preparation_diagnostics = prepare_units(
                    source_roots,
                    lambda path: self._config_for_file(preparation_config, path),
                    None,
                    prepared_units=prepared_source_units,
                    jobs=resolved_jobs,
                )
                source_preparation_diagnostics = tuple(sorted(set(
                    source_preparation_diagnostics + scan_preparation_diagnostics
                )))

            if active_profiles:
                classification_keys = {profile_key(profile.flags) for profile in active_profiles}
            else:
                classification_keys = {profile_key(preparation_config.defined_syms)}

            included_headers: Set[str] = set()
            for units in prepared_source_units.values():
                for key, prepared in units.items():
                    if key in classification_keys:
                        included_headers.update(prepared.expanded.included_files)

            orphan_headers: List[str] = []
            for h_path in headers:
                real_h = os.path.realpath(h_path)
                if real_h not in included_headers:
                    orphan_headers.append(h_path)
                    display_path = os.path.relpath(h_path, base_dir) if os.path.exists(base_dir) else os.path.basename(h_path)
                    if not quiet:
                        sys.stderr.write(f"Note: Scanning orphan header '{display_path}' as standalone root (not included by any scanned C source file).\n")
                        sys.stderr.flush()
                    logger.info("Scanning orphan header '%s' as standalone root (not included by any scanned C source file).", display_path)

            files_to_scan = source_roots + orphan_headers

        total_files = len(files_to_scan)
        if total_files > 0:
            resolved_jobs = min(resolved_jobs, total_files)

        logger.info("Starting scan of target path '%s' (jobs=%d, strategy=%s)", report_target_str, resolved_jobs, config_strategy or getattr(self.config, "config_strategy", "one-at-a-time"))
        logger.debug("Discovered %d total files to scan (%d ignored)", len(files_to_scan), len(ignored_paths))

        if seed_profiles and not quiet:
            _validate_seed_flags_diagnostics(files_to_scan, seed_profiles, quiet=quiet)

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

        from .project_analysis import prepare_project

        self._project_units = prepared_source_units
        self.project_diagnostics = source_preparation_diagnostics
        try:
            if len(files_to_scan) > 1 and config.engine_mode != AnalysisEngine.REGEX:
                self._project_units, project_diagnostics = prepare_project(
                    files_to_scan,
                    lambda path: self._config_for_file(config, path),
                    profiles,
                    prepared_units=self._project_units,
                    jobs=resolved_jobs,
                )
                self.project_diagnostics = tuple(sorted(set(
                    self.project_diagnostics + project_diagnostics
                )))

            for diagnostic in self.project_diagnostics:
                logger.log(logging.INFO if quiet else logging.WARNING, "%s", diagnostic)

            progress_active = (progress_callback is not None) and (not quiet)
            if resolved_jobs > 1:
                results = self._scan_files_parallel(files_to_scan, resolved_jobs, config, progress_callback, quiet=quiet, progress_active=progress_active, profiles=profiles)
            else:
                results = self._scan_files_sequential(files_to_scan, config, progress_callback, quiet=quiet, progress_active=progress_active, profiles=profiles)
        finally:
            self._project_units = {}

        analyzed_count = 0
        failed_count = 0

        real_base_dir = os.path.realpath(base_dir)
        # Stable fingerprints are the finalized logical finding identity.
        # Per-file dedup removes analyzer-path/profile duplicates. The global
        # map additionally merges the same header-origin finding across TUs
        # when header deduplication is enabled.
        dedup_candidates: List[Issue] = []
        dedup_headers = getattr(config, "dedup_headers", True)
        
        for file_path, file_issues, loc, duration_ms, parser_status, parse_tier, file_status, file_confidence, scan_err, parse_attempts in results:
            display_path = os.path.relpath(file_path, base_dir) if os.path.exists(base_dir) else os.path.basename(file_path)
            real_file_path = os.path.realpath(file_path)

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
                    # original_path is the provenance file path (header or translation unit)
                    original_path = issue.file_path
                    real_origin_path = os.path.realpath(original_path)
                    try:
                        canonical_rel_path = os.path.relpath(real_origin_path, real_base_dir)
                    except ValueError:
                        canonical_rel_path = real_origin_path

                    normalized_canonical_path = canonical_rel_path.replace("\\", "/")

                    # Compute stable project-relative fingerprint without line numbers.
                    # This is the final identity used by baselines and SARIF.
                    issue.fingerprint = compute_issue_fingerprint(
                        issue.rule_id,
                        normalized_canonical_path,
                        issue.code_snippet,
                    )

                    # Determine if this issue originates from a different file (e.g., a header)
                    is_from_header = real_origin_path != real_file_path

                    # Preserve the canonical header path as the primary location in both modes
                    if is_from_header:
                        try:
                            issue.file_path = os.path.relpath(original_path, base_dir)
                        except ValueError:
                            issue.file_path = canonical_rel_path
                        if display_path not in issue.related_tus:
                            issue.related_tus.append(display_path)
                    else:
                        issue.file_path = display_path

                    # Normalize any absolute paths in related_tus
                    norm_related: List[str] = []
                    for related in issue.related_tus:
                        if os.path.isabs(related):
                            try:
                                norm_related.append(os.path.relpath(os.path.realpath(related), real_base_dir))
                            except ValueError:
                                norm_related.append(related)
                        else:
                            norm_related.append(related)
                    issue.related_tus = sorted(set(norm_related))

                file_issues = _deduplicate_issues_by_fingerprint(file_issues)

                if dedup_headers:
                    dedup_candidates.extend(file_issues)
                else:
                    # Preserve the explicit per-TU mode while still collapsing
                    # duplicate analyzer paths inside each translation unit.
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
                parse_attempts=report_attempts(parse_attempts, base_dir),
            ))

        if dedup_headers:
            # Per-file finalization is used for file summaries. Rebuild each
            # base fingerprint from canonical source provenance here so
            # occurrence numbering is global and identical across TUs.
            for issue in dedup_candidates:
                issue.fingerprint = compute_issue_fingerprint(
                    issue.rule_id,
                    str(issue.file_path).replace("\\", "/"),
                    issue.code_snippet,
                )
            all_issues.extend(_deduplicate_issues_by_fingerprint(dedup_candidates))

        duration = time.time() - start_time
        logger.info("Scan completed for '%s' in %.2fs: %d files analyzed, %d issues, %d failed", report_target_str, duration, analyzed_count, len(all_issues), failed_count)
        high_total = sum(1 for i in all_issues if i.impact == Severity.HIGH)
        med_total = sum(1 for i in all_issues if i.impact == Severity.MEDIUM)
        low_total = sum(1 for i in all_issues if i.impact == Severity.LOW)

        # Keep report output stable/deterministic regardless of scan order
        # (matters once parallel scanning can complete files out of order).
        file_summaries.sort(key=lambda fs: fs.file_path)
        all_issues.sort(key=lambda i: (i.file_path, i.line_number, i.column_number, i.rule_id, i.message))
        failed_paths.sort()
        scan_errors.sort(key=lambda e: (e.file_path, e.error_type, e.message))

        rel_ignored = [os.path.relpath(p, base_dir) if os.path.exists(base_dir) else os.path.basename(p) for p in ignored_paths]
        rel_ignored.sort()
        files_discovered = len(files_to_scan) + len(ignored_paths)

        return ScanResult(
            target_path=report_target_str,
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

    def _config_for_file(self, config, file_path):
        return config

    def _prepared_config_for_file(self, config, file_path):
        import copy

        config = self._config_for_file(config, file_path)
        prepared = getattr(self, "_project_units", {}).get(file_path)
        if prepared:
            config = copy.copy(config)
            config.prepared_units = prepared
        return config

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
                file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err, parse_attempts = self._scan_single_file_content(file_path, content, config=self._prepared_config_for_file(config, file_path), profiles=profiles, quiet=quiet, progress_active=progress_active)
                results.append((file_path, file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err, parse_attempts))
            except Exception as e:
                scan_err = ScanError(
                    file_path=file_path,
                    error_type=type(e).__name__,
                    message=str(e) or f"Failed to read file: {file_path}",
                )
                _emit_error(file_path, scan_err.error_type, scan_err.message, quiet=quiet, progress_active=progress_active)
                results.append((file_path, [], 0, 0.0, ParserStatus.PARSE_FAILED.value, ParseTier.REGEX_FALLBACK.value, "failed", Confidence.LIMITED.value, scan_err, []))
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
        futures = {}
        with multiprocessing_logging_context() as (log_queue, effective_log_level):
            try:
                futures = {
                    pool.submit(
                        _scan_file_worker,
                        file_path,
                        self._prepared_config_for_file(config, file_path),
                        profiles,
                        quiet,
                        progress_active,
                        log_queue,
                        effective_log_level,
                    ): file_path
                    for file_path in files_to_scan
                }
                for future in as_completed(futures):
                    file_path = futures[future]
                    completed_count += 1
                    try:
                        file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err, parse_attempts = future.result()
                        results.append((file_path, file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err, parse_attempts))
                    except Exception as e:
                        scan_err = ScanError(
                            file_path=file_path,
                            error_type=type(e).__name__,
                            message=str(e) or f"Worker execution failed for {file_path}",
                        )
                        _emit_error(file_path, scan_err.error_type, scan_err.message, quiet=quiet, progress_active=progress_active)
                        results.append((file_path, [], 0, 0.0, ParserStatus.PARSE_FAILED.value, ParseTier.REGEX_FALLBACK.value, "failed", Confidence.LIMITED.value, scan_err, []))
                    if progress_callback:
                        progress_callback(completed_count, total_files, file_path)
                pool.shutdown(wait=True)
            except BaseException:
                procs = list((getattr(pool, "_processes", {}) or {}).values())
                for future in futures:
                    future.cancel()
                for p in procs:
                    if p and p.is_alive():
                        p.terminate()

                # Reap terminated children so Windows does not retain worker
                # handles or a queue-management thread until interpreter exit.
                join_deadline = time.monotonic() + 1.0
                for p in procs:
                    if p:
                        p.join(timeout=max(0.0, join_deadline - time.monotonic()))

                # terminate() should be sufficient, but use kill() where available
                # for a worker that did not exit within the bounded grace period.
                for p in procs:
                    if p and p.is_alive() and hasattr(p, "kill"):
                        p.kill()
                for p in procs:
                    if p and p.is_alive():
                        p.join(timeout=0.5)

                # Join the executor manager thread after its workers have been
                # reaped. shutdown(wait=False) leaves that non-daemon thread alive
                # on Windows/Python 3.10 and prevents the interpreter from exiting.
                pool.shutdown(wait=True, cancel_futures=True)
                raise
        return results

    def scan_text(
        self,
        source_code: str,
        file_path: str = "source.c",
        quiet: bool = False,
        profiles: Optional[List[ConfigProfile]] = None,
        config_strategy: Optional[str] = None,
        exhaustive_threshold: Optional[int] = None,
    ) -> ScanResult:
        """
        Directly scans in-memory C source text.
        """
        HEADER_CACHE.clear()
        start_time = time.time()
        config = self._get_active_config()
        self.config = config
        self.rules = config.get_rules()

        if profiles is None and (config_strategy is not None or getattr(self.config, "config_strategy", "one-at-a-time") != "one-at-a-time"):
            strat = config_strategy if config_strategy is not None else getattr(self.config, "config_strategy", "one-at-a-time")
            ex_thresh = exhaustive_threshold if exhaustive_threshold is not None else getattr(self.config, "exhaustive_threshold", 10)
            from .utils import strip_comments_keep_lines
            from .ast_analyzer import ConditionalFlagCollector, generate_config_profiles
            _, clean_code = strip_comments_keep_lines(source_code)
            res = ConditionalFlagCollector.collect(clean_code)
            profiles = generate_config_profiles(
                res.presence_flags,
                strategy=strat,
                exhaustive_threshold=ex_thresh,
                base_flags=self.config.defined_syms,
            )

        if profiles is None and config_strategy is not None:
            strat = config_strategy
            ex_thresh = exhaustive_threshold if exhaustive_threshold is not None else getattr(self.config, "exhaustive_threshold", 10)
            from .utils import strip_comments_keep_lines
            from .ast_analyzer import ConditionalFlagCollector, generate_config_profiles
            _, clean_code = strip_comments_keep_lines(source_code)
            res = ConditionalFlagCollector.collect(clean_code)
            if res.presence_flags or strat == "baseline":
                profiles = generate_config_profiles(
                    res.presence_flags,
                    strategy=strat,
                    exhaustive_threshold=ex_thresh,
                    base_flags=self.config.defined_syms,
                )

        file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err, parse_attempts = self._scan_single_file_content(file_path, source_code, config=config, profiles=profiles, quiet=quiet)
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

        file_issues = _deduplicate_issues_by_fingerprint(file_issues)

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
                parse_attempts=report_attempts(parse_attempts),
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
    ) -> Tuple[List[Issue], int, float, str, str, str, str, Optional[ScanError], List[Dict[str, Any]]]:
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
) -> Tuple[List[Issue], int, float, str, str, str, str, Optional[ScanError], List[Dict[str, Any]]]:
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
    original_lines = content.splitlines()
    orig_loc = len(original_lines)

    inc_roots = config.include_roots if config else []
    source_dir = os.path.dirname(os.path.abspath(file_path)) if file_path and file_path != "source.c" else os.getcwd()
    resolver = IncludeResolver(include_roots=inc_roots, base_dir=source_dir)
    expander = TUIncludeExpander(resolver=resolver, defined_syms=config.defined_syms if config else None)
    from .project_analysis import profile_key

    prepared = config.prepared_units.get(profile_key(config.defined_syms)) if config else None
    if prepared is not None and prepared.source != content:
        prepared = None
    tu = prepared.expanded if prepared else expander.expand(content, source_path=file_path)
    content = tu.expanded_text
    line_map = tu.line_map

    ast_parser = ast_parser or CASTParser()
    raw_lines = content.splitlines()
    loc = orig_loc
    issues: List[Issue] = []
    seen_keys: Set[str] = set()

    suppressions = SuppressionMap.from_source(original_lines) if enable_suppressions else None

    # Cache per-file suppression maps so inline ignore comments work across included headers
    file_suppressions: Dict[str, SuppressionMap] = {
        file_path: suppressions if suppressions is not None else SuppressionMap.from_source([]),
        os.path.realpath(file_path): suppressions if suppressions is not None else SuppressionMap.from_source([])
    }

    def get_suppression_map(f_path: str) -> Optional[SuppressionMap]:
        if not enable_suppressions:
            return None
        if f_path in file_suppressions:
            return file_suppressions[f_path]
        try:
            if os.path.isfile(f_path):
                with open(f_path, "r", encoding="utf-8", errors="replace") as f:
                    file_lines = f.read().splitlines()
                file_suppressions[f_path] = SuppressionMap.from_source(file_lines)
            else:
                file_suppressions[f_path] = SuppressionMap.from_source([])
        except Exception:
            file_suppressions[f_path] = SuppressionMap.from_source([])
        return file_suppressions[f_path]

    def add_issue_if_unique(issue: Issue):
        exp_line = issue.line_number
        src_loc = line_map.get(exp_line)
        if src_loc and src_loc.is_analysis:
            return
        if src_loc:
            orig_file = src_loc.file_path
            orig_line = src_loc.line_number
            orig_snippet = src_loc.line_content.strip()
        else:
            orig_file = file_path
            orig_line = exp_line
            orig_snippet = raw_lines[exp_line - 1].strip() if 0 < exp_line <= len(raw_lines) else ""

        # A verified multiline write must retain its complete original statement.
        # Reject spans that cross provenance boundaries or collapse source lines.
        if issue.expanded_end_line is not None and issue.expanded_end_line > exp_line:
            locations = [line_map.get(line) for line in range(exp_line, issue.expanded_end_line + 1)]
            if not src_loc or any(
                location is None or location.is_analysis
                or location.file_path != orig_file
                or location.line_number != orig_line + offset
                for offset, location in enumerate(locations)
            ):
                return
            orig_snippet = "\n".join(location.line_content for location in locations).strip()
        issue.expanded_end_line = None

        f_supp = get_suppression_map(orig_file)
        if f_supp and f_supp.is_suppressed(orig_line, issue.rule_id):
            return
        if sev_filter and issue.impact not in sev_filter:
            return

        issue.file_path = orig_file
        issue.line_number = orig_line
        issue.code_snippet = orig_snippet

        key = f"{issue.rule_id}:{issue.file_path}:{issue.line_number}:{issue.message}"
        if key not in seen_keys:
            seen_keys.add(key)
            issues.append(issue)

    parser_status = ParserStatus.FALLBACK_PARSER.value
    parse_tier = ParseTier.REGEX_FALLBACK.value
    file_status = "success"
    confidence_val = Confidence.FALLBACK.value
    scan_error: Optional[ScanError] = None
    parse_attempts = []

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
            ast_ctx = prepared.context if prepared else ast_parser.parse(content, defined_syms=config.defined_syms if config else None)
            clean_lines = ast_ctx.clean_source.splitlines()
            clean_code = ast_ctx.clean_source
            parser_status = ast_ctx.parser_status
            parse_tier = ast_ctx.parse_tier
            parse_attempts = map_attempts(ast_ctx.parse_attempts, content, line_map, file_path)
            if parse_tier == ParseTier.REGEX_FALLBACK.value:
                logger.debug("%s", format_attempts(file_path, parse_attempts))
            confidence_val = Confidence.FULL.value if parser_status == ParserStatus.PYCPARSER_SUCCESS.value else Confidence.FALLBACK.value

        logger.info("Entering file scan: %s", file_path)

        # Logging configuration is stable during a file scan. Avoid a logging
        # method call for every rule/line pair when TRACE is disabled.
        trace_enabled = logger.isEnabledFor(TRACE_LEVEL_NUM)

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
                    if trace_enabled:
                        logger.log(TRACE_LEVEL_NUM, "Executing regex rule %s (%s) on %s:%d", rule.rule_id, rule.name, file_path, line_no)
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
                if trace_enabled:
                    logger.log(TRACE_LEVEL_NUM, "Executing AST rule %s (%s) on %s", rule.rule_id, rule.name, file_path)
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
    logger.info("Leaving file scan: %s (status=%s, parse_tier=%s, issues=%d, duration=%.2fms)", file_path, file_status, parse_tier, len(issues), duration_ms)
    return issues, loc, duration_ms, parser_status, parse_tier, file_status, confidence_val, scan_error, parse_attempts


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
) -> Tuple[List[Issue], int, float, str, str, str, str, Optional[ScanError], List[Dict[str, Any]]]:
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

    # Deduplicate requested profiles preserving order
    deduped_profiles: List[ConfigProfile] = []
    seen_p: Set[ConfigProfile] = set()
    for p in profiles:
        if p not in seen_p:
            seen_p.add(p)
            deduped_profiles.append(p)
    profiles = deduped_profiles

    if config is not None:
        base_rules = config.get_rules()
        base_engine_mode = config.engine_mode
        base_sev_filter = config.severity_filter
        base_enable_suppressions = config.enable_inline_suppressions
        base_suppression_config = config.suppression_config
        base_include_roots = config.include_roots
        base_dedup_headers = getattr(config, "dedup_headers", True)
        base_mode = getattr(config, "mode", ScanMode.FILE)
    else:
        base_rules = rules if rules is not None else get_all_rules()
        base_engine_mode = engine_mode if engine_mode is not None else AnalysisEngine.HYBRID
        base_sev_filter = None
        base_enable_suppressions = True
        base_suppression_config = {}
        base_include_roots = []
        base_dedup_headers = True
        base_mode = ScanMode.FILE

    total_duration_ms = 0.0
    profile_candidates: List[Issue] = []
    orig_loc = len(content.splitlines())
    loc = orig_loc

    best_parser_status = ParserStatus.PARSE_FAILED.value
    best_parse_tier = ParseTier.REGEX_FALLBACK.value
    best_confidence = Confidence.LIMITED.value
    first_scan_err: Optional[ScanError] = None
    has_profile_failure = False
    parse_attempts = []

    for profile_index, cp in enumerate(profiles):
        variant_config = ScanConfig.create(
            rules=base_rules,
            engine_mode=base_engine_mode,
            severity_filter=base_sev_filter,
            enable_inline_suppressions=base_enable_suppressions,
            suppression_config=base_suppression_config,
            defined_syms=cp.flags,
            include_roots=base_include_roots,
            dedup_headers=base_dedup_headers,
            mode=base_mode,
        )

        variant_config.prepared_units = config.prepared_units if config else {}

        v_issues, v_loc, v_dur, v_parser_status, v_parse_tier, v_status, v_confidence, v_err, v_attempts = _scan_file_content(
            content=content,
            file_path=file_path,
            ast_parser=ast_parser,
            config=variant_config,
            quiet=quiet,
            progress_active=progress_active,
        )

        parse_attempts.extend(dict(attempt, profile=cp.name) for attempt in v_attempts)
        total_duration_ms += v_dur
        loc = max(loc, v_loc)

        if v_status == "failed" or v_err is not None:
            has_profile_failure = True
            if first_scan_err is None:
                first_scan_err = v_err or ScanError(
                    file_path=file_path,
                    error_type="ProfileScanError",
                    message=f"Analysis failed under profile '{cp.name}'",
                )

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
            provenance_path = str(iss.file_path).replace("\\", "/")
            iss.fingerprint = compute_issue_fingerprint(
                iss.rule_id,
                provenance_path,
                iss.code_snippet,
            )
            # Carry profile membership through the shared site-merging path.
            # The private token is converted back to public reachable_under
            # labels after all profile candidates have been coalesced.
            iss.reachable_under = [f"__cgull_profile__:{profile_index}"]
            profile_candidates.append(iss)

    best_file_status = "failed" if has_profile_failure else "success"
    num_profiles = len(profiles)
    final_issues = _deduplicate_issues_by_fingerprint(profile_candidates)

    for iss in final_issues:
        seen_indices = {
            int(label.rsplit(":", 1)[1])
            for label in iss.reachable_under
            if label.startswith("__cgull_profile__:")
        }
        if len(seen_indices) == num_profiles:
            iss.reachable_under = ["unconditional"]
        else:
            iss.reachable_under = sorted({
                profiles[index].reachable_under
                for index in seen_indices
            })

    final_issues.sort(key=lambda x: (x.line_number, x.column_number, x.rule_id, x.message))

    return final_issues, loc, total_duration_ms, best_parser_status, best_parse_tier, best_file_status, best_confidence, first_scan_err, parse_attempts


def _scan_file_worker(
    file_path: str,
    config: Union[ScanConfig, AnalysisEngine],
    profiles: Optional[List[ConfigProfile]] = None,
    quiet: bool = False,
    progress_active: bool = False,
    log_queue: Optional[Any] = None,
    log_level: Optional[int] = None,
) -> Tuple[List[Issue], int, float, str, str, str, str, Optional[ScanError], List[Dict[str, Any]]]:
    """
    Entry point run in a separate process by ProcessPoolExecutor. Rebuilds
    the rules and configuration from the provided ScanConfig.
    """
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level

    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    if log_level is not None:
        root_logger.setLevel(log_level)

    qh = None
    if log_queue is not None:
        from logging.handlers import QueueHandler
        qh = QueueHandler(log_queue)
        qh.setLevel(log_level if log_level is not None else root_logger.level)
        root_logger.addHandler(qh)

    try:
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
            return [], 0, 0.0, ParserStatus.PARSE_FAILED.value, ParseTier.REGEX_FALLBACK.value, "failed", Confidence.LIMITED.value, scan_err, []
        return _scan_file_content_profiles(content, file_path, profiles=profiles, config=config, quiet=quiet, progress_active=progress_active)
    finally:
        if qh is not None:
            root_logger.removeHandler(qh)
        for h in original_handlers:
            if h not in root_logger.handlers:
                root_logger.addHandler(h)
        root_logger.setLevel(original_level)