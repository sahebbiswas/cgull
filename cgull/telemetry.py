"""Rule-neutral scan telemetry and telemetry-aware scanner integration.

The scanner already knows physical source-line counts after each scan unit has
completed. This module aggregates those counters in the coordinator so live
progress never needs to reread source files and worker processes never print
independent progress output.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, replace
import os
import time
from typing import Any, Callable, List, Optional, TextIO

from .engine import CGullScanner as _BaseCGullScanner, _emit_error, _scan_file_worker
from .ignore import CGullIgnoreFilter
from .models import (
    Confidence,
    ConfigProfile,
    ParseTier,
    ParserStatus,
    ScanConfig,
    ScanError,
    ScanResult,
)
from .utils import ProgressIndicator as _BaseProgressIndicator


# Very fast scans can complete inside one platform timer tick. Keep canonical
# elapsed time positive for non-empty analysis so downstream consumers can
# safely recompute throughput, while still avoiding NaN/inf values.
_MIN_ELAPSED_SECONDS = 1e-6


@dataclass(frozen=True)
class ScanTelemetry:
    """Immutable scan-level performance and volume counters."""

    files_discovered: int = 0
    files_scanned: int = 0
    unique_source_lines: int = 0
    analyzed_lines: int = 0
    elapsed_seconds: float = 0.0
    findings_count: int = 0
    parse_fallback_count: int = 0
    scan_error_count: int = 0

    @property
    def throughput_kloc_per_sec(self) -> float:
        if self.analyzed_lines <= 0 or self.elapsed_seconds <= 0.0:
            return 0.0
        return (self.analyzed_lines / 1000.0) / self.elapsed_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_discovered": self.files_discovered,
            "files_scanned": self.files_scanned,
            "unique_source_lines": self.unique_source_lines,
            "analyzed_lines": self.analyzed_lines,
            # Preserve enough precision that a valid non-empty scan never
            # serializes as zero elapsed time. Human reporters round separately.
            "elapsed_seconds": self.elapsed_seconds,
            "throughput_kloc_per_sec": self.throughput_kloc_per_sec,
            "findings_count": self.findings_count,
            "parse_fallback_count": self.parse_fallback_count,
            "scan_error_count": self.scan_error_count,
        }

    def with_findings_count(self, findings_count: int) -> "ScanTelemetry":
        return replace(self, findings_count=max(0, findings_count))


def _safe_elapsed(elapsed: float, analyzed_lines: int) -> float:
    elapsed = max(0.0, elapsed)
    if analyzed_lines > 0:
        return max(_MIN_ELAPSED_SECONDS, elapsed)
    return elapsed


def telemetry_for(result: ScanResult) -> ScanTelemetry:
    """Return authoritative telemetry, deriving legacy results when necessary."""
    telemetry = getattr(result, "telemetry", None)
    if isinstance(telemetry, ScanTelemetry):
        return telemetry

    fallback_count = sum(
        1
        for summary in result.file_summaries
        if summary.status == "success"
        and summary.parser == ParserStatus.FALLBACK_PARSER.value
    )
    files_scanned = result.files_analyzed or result.scanned_files_count
    unique_lines = max(0, result.total_lines_of_code)
    return ScanTelemetry(
        files_discovered=result.files_discovered
        or (result.scanned_files_count + len(result.ignored_paths) + len(result.failed_paths)),
        files_scanned=files_scanned,
        unique_source_lines=unique_lines,
        analyzed_lines=unique_lines,
        elapsed_seconds=_safe_elapsed(result.scan_duration_seconds, unique_lines),
        findings_count=result.total_issues_count,
        parse_fallback_count=fallback_count,
        scan_error_count=len(result.scan_errors),
    )


def _profile_multiplier(profiles: Optional[List[ConfigProfile]]) -> int:
    if not profiles:
        return 1
    # ConfigProfile is hashable and profile scanning itself deduplicates while
    # preserving order, so use the same semantic count for analysis volume.
    return max(1, len(set(profiles)))


class _ProgressUpdateAdapter:
    """Callable legacy progress callback with an explicit telemetry channel."""

    def __init__(self, owner: "ProgressIndicator") -> None:
        self._owner = owner

    def __call__(self, completed: int, total: int, current_file: str = "") -> None:
        self._owner._render(completed, total, current_file)

    def update_telemetry(self, telemetry: ScanTelemetry) -> None:
        self._owner.update_telemetry(telemetry)


class ProgressIndicator(_BaseProgressIndicator):
    """Existing in-place progress indicator enhanced with scan telemetry."""

    def __init__(
        self,
        stream: Optional[TextIO] = None,
        quiet: bool = False,
        bar_width: int = 20,
    ) -> None:
        super().__init__(stream=stream, quiet=quiet, bar_width=bar_width)
        self.telemetry = ScanTelemetry()
        # cli_base passes ``progress.update`` to the scanner. Shadow the class
        # method with a callable adapter so telemetry is an explicit callback
        # protocol rather than inferred from a bound method's ``__self__``.
        self.update = _ProgressUpdateAdapter(self)  # type: ignore[method-assign]

    def update_telemetry(self, telemetry: ScanTelemetry) -> None:
        self.telemetry = telemetry

    def _render(self, completed: int, total: int, current_file: str = "") -> None:
        if self.quiet:
            return

        if total <= 0:
            percentage = 100
            filled_len = self.bar_width
        else:
            percentage = min(100, int((completed / total) * 100))
            filled_len = min(self.bar_width, int(self.bar_width * completed / total))

        bar = "█" * filled_len + "░" * (self.bar_width - filled_len)
        parts = [f"Scanning [{bar}] {percentage}% ({completed}/{total} files)"]
        if self.telemetry.analyzed_lines > 0:
            parts.append(f"{self.telemetry.analyzed_lines / 1000.0:.1f} KLOC")
            parts.append(f"{self.telemetry.throughput_kloc_per_sec:.1f} KLOC/s")
            parts.append(f"{self.telemetry.findings_count} issues")
        if current_file:
            parts.append(str(current_file))
        line = "  •  ".join(parts)

        padded_line = line.ljust(self.last_line_len)
        self.stream.write(f"\r{padded_line}")
        self.stream.flush()
        self.last_line_len = max(self.last_line_len, len(padded_line))


class _CountingIgnoreFilter:
    """Delegate ignore decisions while recording ignored physical files once."""

    def __init__(self, delegate: CGullIgnoreFilter, ignored_files: set[str]) -> None:
        self._delegate = delegate
        self._ignored_files = ignored_files

    def should_ignore(self, path: str) -> bool:
        ignored = self._delegate.should_ignore(path)
        if ignored and os.path.isfile(path):
            self._ignored_files.add(os.path.normcase(os.path.realpath(path)))
        return ignored

    def should_prune_dir(self, path: str) -> bool:
        return self._delegate.should_prune_dir(path)

    def load_from_file(self, path: str) -> None:
        self._delegate.load_from_file(path)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


class CGullScanner(_BaseCGullScanner):
    """Telemetry-aware drop-in scanner preserving the established API."""

    def _begin_telemetry(self) -> None:
        self._telemetry_started_at = time.monotonic()
        self._telemetry_unique_lines = 0
        self._telemetry_analyzed_lines = 0
        self._telemetry_findings = 0
        self._telemetry_fallbacks = 0
        self._telemetry_errors = 0
        self._telemetry_files_scanned = 0
        self._telemetry_progress_completed = 0
        self._telemetry_total_files = 0
        self._telemetry_issue_keys: set[tuple[Any, ...]] = set()
        self._telemetry_ignored_files: set[str] = set()
        self._telemetry_callback: Optional[Callable[[ScanTelemetry], None]] = None

    def _prepare_counting_ignore_filter(self, target_path, custom_ignore_patterns=None) -> None:
        if isinstance(self.ignore_filter, _CountingIgnoreFilter):
            self.ignore_filter._ignored_files = self._telemetry_ignored_files
            return
        if self.ignore_filter is not None:
            self.ignore_filter = _CountingIgnoreFilter(
                self.ignore_filter,
                self._telemetry_ignored_files,
            )
            return

        raw_targets = list(target_path) if isinstance(target_path, (list, tuple)) else [target_path]
        abs_targets = [os.path.abspath(path) for path in raw_targets]
        if len(abs_targets) == 1:
            target = abs_targets[0]
            base_dir = target if os.path.isdir(target) else (os.path.dirname(target) or ".")
        else:
            try:
                common_path = os.path.commonpath(abs_targets)
                base_dir = common_path if os.path.isdir(common_path) else os.path.dirname(common_path)
            except ValueError:
                base_dir = os.getcwd()

        delegate = CGullIgnoreFilter(
            base_dir=base_dir,
            custom_patterns=custom_ignore_patterns,
        )
        self.ignore_filter = _CountingIgnoreFilter(
            delegate,
            self._telemetry_ignored_files,
        )

    def _snapshot(self) -> ScanTelemetry:
        started = getattr(self, "_telemetry_started_at", time.monotonic())
        analyzed_lines = getattr(self, "_telemetry_analyzed_lines", 0)
        return ScanTelemetry(
            files_discovered=(
                getattr(self, "_telemetry_total_files", 0)
                + len(getattr(self, "_telemetry_ignored_files", set()))
            ),
            files_scanned=getattr(self, "_telemetry_files_scanned", 0),
            unique_source_lines=getattr(self, "_telemetry_unique_lines", 0),
            analyzed_lines=analyzed_lines,
            elapsed_seconds=_safe_elapsed(time.monotonic() - started, analyzed_lines),
            findings_count=getattr(self, "_telemetry_findings", 0),
            parse_fallback_count=getattr(self, "_telemetry_fallbacks", 0),
            scan_error_count=getattr(self, "_telemetry_errors", 0),
        )

    @staticmethod
    def _live_issue_key(issue: Any) -> tuple[Any, ...]:
        raw_path = str(getattr(issue, "file_path", ""))
        canonical_path = os.path.normcase(os.path.realpath(raw_path)) if raw_path else ""
        snippet = " ".join(str(getattr(issue, "code_snippet", "")).split())
        return (
            getattr(issue, "rule_id", ""),
            canonical_path,
            getattr(issue, "line_number", 0),
            getattr(issue, "column_number", 1),
            getattr(issue, "message", ""),
            snippet,
        )

    def _record_live_findings(self, file_issues: List[Any], status: str) -> None:
        if status != "success":
            return
        dedup_headers = bool(getattr(self.config, "dedup_headers", True))
        for issue in file_issues:
            if self.severity_filter and issue.impact not in self.severity_filter:
                continue
            if dedup_headers:
                key = self._live_issue_key(issue)
                if key in self._telemetry_issue_keys:
                    continue
                self._telemetry_issue_keys.add(key)
            self._telemetry_findings += 1

    def _record_progress_result(
        self,
        *,
        loc: int,
        file_issues: List[Any],
        parser_status: str,
        status: str,
        multiplier: int,
        completed: int,
        total: int,
        progress_callback,
        current_file: str,
    ) -> None:
        self._telemetry_progress_completed = completed
        self._telemetry_total_files = total
        self._telemetry_unique_lines += max(0, loc)
        self._telemetry_analyzed_lines += max(0, loc) * max(1, multiplier)
        self._record_live_findings(file_issues, status)
        if status == "success":
            self._telemetry_files_scanned += 1
            if parser_status == ParserStatus.FALLBACK_PARSER.value:
                self._telemetry_fallbacks += 1
        else:
            self._telemetry_errors += 1

        snapshot = self._snapshot()
        telemetry_callback = getattr(self, "_telemetry_callback", None)
        if callable(telemetry_callback):
            telemetry_callback(snapshot)
        if progress_callback:
            progress_callback(completed, total, current_file)

    def _config_for_file(self, config: ScanConfig, file_path: str) -> ScanConfig:
        """Return scan configuration for one file; subclasses may add per-TU context."""
        return config

    def scan_path(
        self,
        *args,
        telemetry_callback: Optional[Callable[[ScanTelemetry], None]] = None,
        **kwargs,
    ) -> ScanResult:
        self._begin_telemetry()

        target_path = kwargs.get("target_path")
        if target_path is None and args:
            target_path = args[0]
        custom_ignore_patterns = kwargs.get("custom_ignore_patterns")
        if custom_ignore_patterns is None and len(args) >= 3:
            custom_ignore_patterns = args[2]
        if target_path is not None:
            self._prepare_counting_ignore_filter(target_path, custom_ignore_patterns)

        progress_callback = kwargs.get("progress_callback")
        if progress_callback is None and len(args) >= 5:
            progress_callback = args[4]
        if telemetry_callback is not None:
            self._telemetry_callback = telemetry_callback
        else:
            # The standard ProgressIndicator exposes telemetry directly on its
            # callable adapter. Other callers can pass telemetry_callback=...
            # explicitly without needing a bound-method callback.
            progress_telemetry = getattr(progress_callback, "update_telemetry", None)
            if callable(progress_telemetry):
                self._telemetry_callback = progress_telemetry

        result = super().scan_path(*args, **kwargs)
        analyzed_lines = max(
            max(0, result.total_lines_of_code),
            getattr(self, "_telemetry_analyzed_lines", 0),
        )
        elapsed = _safe_elapsed(
            time.monotonic() - self._telemetry_started_at,
            analyzed_lines,
        )
        final = ScanTelemetry(
            files_discovered=result.files_discovered
            or (result.scanned_files_count + len(result.ignored_paths) + len(result.failed_paths)),
            files_scanned=result.files_analyzed or result.scanned_files_count,
            unique_source_lines=max(0, result.total_lines_of_code),
            analyzed_lines=analyzed_lines,
            elapsed_seconds=elapsed,
            findings_count=result.total_issues_count,
            parse_fallback_count=sum(
                1
                for summary in result.file_summaries
                if summary.status == "success"
                and summary.parser == ParserStatus.FALLBACK_PARSER.value
            ),
            scan_error_count=len(result.scan_errors),
        )
        result.telemetry = final
        return result

    def scan_text(self, *args, **kwargs) -> ScanResult:
        started = time.monotonic()
        result = super().scan_text(*args, **kwargs)
        profiles = kwargs.get("profiles")
        if profiles is None and len(args) >= 4:
            profiles = args[3]
        multiplier = _profile_multiplier(profiles)
        unique_lines = max(0, result.total_lines_of_code)
        analyzed_lines = unique_lines * multiplier
        result.telemetry = ScanTelemetry(
            files_discovered=result.files_discovered or 1,
            files_scanned=result.files_analyzed or result.scanned_files_count,
            unique_source_lines=unique_lines,
            analyzed_lines=analyzed_lines,
            elapsed_seconds=_safe_elapsed(time.monotonic() - started, analyzed_lines),
            findings_count=result.total_issues_count,
            parse_fallback_count=sum(
                1
                for summary in result.file_summaries
                if summary.status == "success"
                and summary.parser == ParserStatus.FALLBACK_PARSER.value
            ),
            scan_error_count=len(result.scan_errors),
        )
        return result

    def _scan_files_sequential(
        self,
        files_to_scan: List[str],
        config: ScanConfig,
        progress_callback=None,
        quiet: bool = False,
        progress_active: bool = False,
        profiles: Optional[List[ConfigProfile]] = None,
    ):
        results = []
        total_files = len(files_to_scan)
        multiplier = _profile_multiplier(profiles)
        for idx, file_path in enumerate(files_to_scan, 1):
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err = self._scan_single_file_content(
                    file_path,
                    content,
                    config=self._prepared_config_for_file(config, file_path),
                    profiles=profiles,
                    quiet=quiet,
                    progress_active=progress_active,
                )
                result = (file_path, file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err)
            except Exception as e:
                scan_err = ScanError(
                    file_path=file_path,
                    error_type=type(e).__name__,
                    message=str(e) or f"Failed to read file: {file_path}",
                )
                _emit_error(file_path, scan_err.error_type, scan_err.message, quiet=quiet, progress_active=progress_active)
                result = (
                    file_path,
                    [],
                    0,
                    0.0,
                    ParserStatus.PARSE_FAILED.value,
                    ParseTier.REGEX_FALLBACK.value,
                    "failed",
                    Confidence.LIMITED.value,
                    scan_err,
                )
            results.append(result)
            _, file_issues, loc, _, parser_status, _, status, _, _ = result
            self._record_progress_result(
                loc=loc,
                file_issues=file_issues,
                parser_status=parser_status,
                status=status,
                multiplier=multiplier,
                completed=idx,
                total=total_files,
                progress_callback=progress_callback,
                current_file=file_path,
            )
        return results

    def _scan_files_parallel(
        self,
        files_to_scan: List[str],
        jobs: int,
        config: ScanConfig,
        progress_callback=None,
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
                "Ensure all custom rules and profiles are picklable or use jobs=1 for sequential scanning."
            ) from e

        results = []
        total_files = len(files_to_scan)
        multiplier = _profile_multiplier(profiles)
        completed_count = 0
        pool = ProcessPoolExecutor(max_workers=jobs)
        futures = {}
        try:
            futures = {
                pool.submit(
                    _scan_file_worker,
                    file_path,
                    self._prepared_config_for_file(config, file_path),
                    profiles,
                    quiet,
                    progress_active,
                ): file_path
                for file_path in files_to_scan
            }
            for future in as_completed(futures):
                file_path = futures[future]
                completed_count += 1
                try:
                    file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err = future.result()
                    result = (file_path, file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err)
                except Exception as e:
                    scan_err = ScanError(
                        file_path=file_path,
                        error_type=type(e).__name__,
                        message=str(e) or f"Worker execution failed for {file_path}",
                    )
                    _emit_error(file_path, scan_err.error_type, scan_err.message, quiet=quiet, progress_active=progress_active)
                    result = (
                        file_path,
                        [],
                        0,
                        0.0,
                        ParserStatus.PARSE_FAILED.value,
                        ParseTier.REGEX_FALLBACK.value,
                        "failed",
                        Confidence.LIMITED.value,
                        scan_err,
                    )
                results.append(result)
                _, file_issues, loc, _, parser_status, _, status, _, _ = result
                self._record_progress_result(
                    loc=loc,
                    file_issues=file_issues,
                    parser_status=parser_status,
                    status=status,
                    multiplier=multiplier,
                    completed=completed_count,
                    total=total_files,
                    progress_callback=progress_callback,
                    current_file=file_path,
                )
            pool.shutdown(wait=True)
        except BaseException:
            procs = list((getattr(pool, "_processes", {}) or {}).values())
            for future in futures:
                future.cancel()
            for process in procs:
                if process and process.is_alive():
                    process.terminate()

            join_deadline = time.monotonic() + 1.0
            for process in procs:
                if process:
                    process.join(timeout=max(0.0, join_deadline - time.monotonic()))
            for process in procs:
                if process and process.is_alive() and hasattr(process, "kill"):
                    process.kill()
            for process in procs:
                if process and process.is_alive():
                    process.join(timeout=0.5)
            pool.shutdown(wait=True, cancel_futures=True)
            raise
        return results
