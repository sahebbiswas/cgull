"""Persistent multiprocessing worker context for parallel file scans.

The coordinator keeps expensive rule/configuration setup out of per-file tasks.
On ``fork`` platforms prepared project units are inherited copy-on-write; on
spawn-style platforms workers prepare a local TU only when compact cross-TU
summary imports need to be reattached.
"""
from __future__ import annotations

import copy
import logging
import multiprocessing
import os
import pickle
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, fields
from logging.handlers import QueueHandler
from typing import Any, Dict, List, Optional, Tuple

from .engine import _emit_error, _scan_file_content_profiles
from .logging_config import multiprocessing_logging_context
from .models import (
    Confidence,
    ConfigProfile,
    ParseTier,
    ParserStatus,
    ScanConfig,
    ScanError,
)


_CONFIG_FIELDS = tuple(
    field.name for field in fields(ScanConfig)
    if field.name not in {"rules", "prepared_units"}
)


@dataclass(frozen=True)
class ParallelScanWorkItem:
    """Compact, picklable description of one file scan."""

    file_path: str
    config_overrides: Tuple[Tuple[str, Any], ...] = ()
    project_summaries: Optional[Dict[Any, Any]] = None


@dataclass
class _WorkerState:
    config: ScanConfig
    profiles: Optional[List[ConfigProfile]]
    quiet: bool
    progress_active: bool
    project_units: Dict[str, Dict[Any, Any]]


_WORKER_STATE: Optional[_WorkerState] = None
_WORKER_QUEUE_HANDLER: Optional[QueueHandler] = None


def _configure_worker_logging(log_queue: Optional[Any], log_level: Optional[int]) -> None:
    """Install the queue transport once for the lifetime of a scan worker."""
    global _WORKER_QUEUE_HANDLER

    root_logger = logging.getLogger()
    if _WORKER_QUEUE_HANDLER is not None:
        root_logger.removeHandler(_WORKER_QUEUE_HANDLER)
        _WORKER_QUEUE_HANDLER = None

    # Spawned workers can inherit/bootstrap handlers independently. Route their
    # records only through the coordinator queue when one is available.
    if log_queue is not None:
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)

    if log_level is not None:
        root_logger.setLevel(log_level)

    if log_queue is not None:
        queue_handler = QueueHandler(log_queue)
        queue_handler.setLevel(log_level if log_level is not None else root_logger.level)
        root_logger.addHandler(queue_handler)
        _WORKER_QUEUE_HANDLER = queue_handler


def _initialize_scan_worker(
    config: ScanConfig,
    profiles: Optional[List[ConfigProfile]],
    quiet: bool,
    progress_active: bool,
    log_queue: Optional[Any],
    log_level: Optional[int],
    project_units: Optional[Dict[str, Dict[Any, Any]]] = None,
) -> None:
    """Initialize immutable/common scan state exactly once in each process."""
    global _WORKER_STATE

    worker_config = copy.copy(config)
    worker_config.prepared_units = {}
    _configure_worker_logging(log_queue, log_level)
    _WORKER_STATE = _WorkerState(
        config=worker_config,
        profiles=profiles,
        quiet=quiet,
        progress_active=progress_active,
        project_units=project_units or {},
    )


def _config_for_work_item(state: _WorkerState, item: ParallelScanWorkItem) -> ScanConfig:
    config = copy.copy(state.config)
    for name, value in item.config_overrides:
        setattr(config, name, value)
    config.prepared_units = {}
    return config


def _prepare_local_summary_units(
    item: ParallelScanWorkItem,
    config: ScanConfig,
    profiles: Optional[List[ConfigProfile]],
) -> Dict[Any, Any]:
    """Rebuild a TU locally and attach compact cross-TU imports on spawn."""
    if not item.project_summaries:
        return {}

    from .project_analysis import prepare_units

    prepared, _ = prepare_units(
        [item.file_path],
        lambda _path: config,
        profiles=profiles,
        jobs=1,
    )
    units = prepared.get(item.file_path, {})
    for profile, summaries in item.project_summaries.items():
        unit = units.get(profile)
        if unit is None:
            continue
        context = unit.context
        if context is None:
            continue
        context.project_summaries = summaries
        # A locally parsed context must derive its own caches from the imported
        # summaries; never carry a coordinator AnalysisSession across processes.
        context.analysis_session = None
    return units


def _scan_worker_item(
    item: ParallelScanWorkItem,
):
    """Execute one compact work item using the process-local scan context."""
    state = _WORKER_STATE
    if state is None:
        raise RuntimeError("parallel scan worker was not initialized")

    config = _config_for_work_item(state, item)
    prepared = state.project_units.get(item.file_path)
    if prepared:
        config.prepared_units = prepared
    elif item.project_summaries:
        config.prepared_units = _prepare_local_summary_units(
            item,
            config,
            state.profiles,
        )

    try:
        with open(item.file_path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
    except Exception as exc:
        scan_err = ScanError(
            file_path=item.file_path,
            error_type=type(exc).__name__,
            message=str(exc) or f"Failed to read file: {item.file_path}",
        )
        _emit_error(
            item.file_path,
            scan_err.error_type,
            scan_err.message,
            quiet=state.quiet,
            progress_active=state.progress_active,
        )
        return (
            [],
            0,
            0.0,
            ParserStatus.PARSE_FAILED.value,
            ParseTier.REGEX_FALLBACK.value,
            "failed",
            Confidence.LIMITED.value,
            scan_err,
            [],
        )

    return _scan_file_content_profiles(
        content,
        item.file_path,
        profiles=state.profiles,
        config=config,
        quiet=state.quiet,
        progress_active=state.progress_active,
    )


def _project_summary_payload(scanner: Any, file_path: str) -> Optional[Dict[Any, Any]]:
    """Extract only cross-TU imports; never include AST/session objects."""
    overlays: Dict[Any, Any] = {}
    for profile, unit in getattr(scanner, "_project_units", {}).get(file_path, {}).items():
        context = getattr(unit, "_context", None)
        if context is None:
            continue
        summaries = getattr(context, "project_summaries", None)
        if summaries:
            overlays[profile] = summaries
    return overlays or None


def _config_overrides(base: ScanConfig, per_file: ScanConfig) -> Tuple[Tuple[str, Any], ...]:
    return tuple(
        (name, getattr(per_file, name))
        for name in _CONFIG_FIELDS
        if getattr(per_file, name) != getattr(base, name)
    )


def build_parallel_work_item(scanner: Any, base_config: ScanConfig, file_path: str) -> ParallelScanWorkItem:
    """Build the descriptor used by the pool and by payload-size benchmarks."""
    per_file = scanner._config_for_file(base_config, file_path)
    return ParallelScanWorkItem(
        file_path=file_path,
        config_overrides=_config_overrides(base_config, per_file),
        project_summaries=_project_summary_payload(scanner, file_path),
    )


def serialized_work_item_size(item: ParallelScanWorkItem) -> int:
    """Return the actual pickle payload size used for benchmark assertions."""
    return len(pickle.dumps(item, protocol=pickle.HIGHEST_PROTOCOL))


def _terminate_pool(pool: ProcessPoolExecutor, futures: Dict[Any, str]) -> None:
    """Promptly cancel/reap child processes after interrupts or coordinator errors."""
    processes = list((getattr(pool, "_processes", {}) or {}).values())
    for future in futures:
        future.cancel()
    for process in processes:
        if process and process.is_alive():
            process.terminate()

    join_deadline = time.monotonic() + 1.0
    for process in processes:
        if process:
            process.join(timeout=max(0.0, join_deadline - time.monotonic()))
    for process in processes:
        if process and process.is_alive() and hasattr(process, "kill"):
            process.kill()
    for process in processes:
        if process and process.is_alive():
            process.join(timeout=0.5)
    pool.shutdown(wait=True, cancel_futures=True)


class ParallelWorkerMixin:
    """Telemetry-compatible persistent-worker implementation for jobs > 1."""

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
        if not files_to_scan:
            return []

        # Custom rules stay supported as concrete objects. They are serialized
        # once per spawned worker, rather than once per submitted file.
        base_config = copy.copy(config)
        base_config.prepared_units = {}
        try:
            pickle.dumps(base_config, protocol=pickle.HIGHEST_PROTOCOL)
            if profiles:
                pickle.dumps(profiles, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as exc:
            raise ValueError(
                f"Configuration/profiles cannot be serialized for parallel worker processes: {exc}. "
                "Ensure all custom rules and profiles are picklable or use jobs=1 for sequential scanning."
            ) from exc

        tasks = [build_parallel_work_item(self, base_config, path) for path in files_to_scan]
        try:
            # Fail before starting children if a compact descriptor accidentally
            # captures a non-picklable object graph.
            for task in tasks:
                pickle.dumps(task, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as exc:
            raise ValueError(
                f"Per-file parallel scan context cannot be serialized: {exc}. "
                "Use jobs=1 or remove non-picklable per-file configuration."
            ) from exc

        context = multiprocessing.get_context()
        start_method = context.get_start_method()
        # Fork can inherit coordinator-prepared ASTs copy-on-write without IPC.
        # Spawn/forkserver intentionally receive no PreparedUnit graph; their
        # work items carry only compact project-summary imports and prepare the
        # local TU in the worker when those imports are needed.
        inherited_project_units = (
            getattr(self, "_project_units", {}) if start_method == "fork" else {}
        )

        results = []
        total_files = len(files_to_scan)
        completed_count = 0
        multiplier = 1
        if profiles:
            multiplier = max(1, len(set(profiles)))

        futures: Dict[Any, str] = {}
        with multiprocessing_logging_context() as (log_queue, effective_log_level):
            pool = ProcessPoolExecutor(
                max_workers=jobs,
                mp_context=context,
                initializer=_initialize_scan_worker,
                initargs=(
                    base_config,
                    profiles,
                    quiet,
                    progress_active,
                    log_queue,
                    effective_log_level,
                    inherited_project_units,
                ),
            )
            try:
                futures = {
                    pool.submit(_scan_worker_item, task): task.file_path
                    for task in tasks
                }
                for future in as_completed(futures):
                    file_path = futures[future]
                    completed_count += 1
                    try:
                        (
                            file_issues,
                            loc,
                            duration_ms,
                            parser_status,
                            parse_tier,
                            status,
                            confidence,
                            scan_err,
                            parse_attempts,
                        ) = future.result()
                        result = (
                            file_path,
                            file_issues,
                            loc,
                            duration_ms,
                            parser_status,
                            parse_tier,
                            status,
                            confidence,
                            scan_err,
                            parse_attempts,
                        )
                    except Exception as exc:
                        scan_err = ScanError(
                            file_path=file_path,
                            error_type=type(exc).__name__,
                            message=str(exc) or f"Worker execution failed for {file_path}",
                        )
                        _emit_error(
                            file_path,
                            scan_err.error_type,
                            scan_err.message,
                            quiet=quiet,
                            progress_active=progress_active,
                        )
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
                            [],
                        )

                    results.append(result)
                    if hasattr(self, "_record_progress_result"):
                        _, file_issues, loc, _, parser_status, _, status, _, _, _ = result
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
                    elif progress_callback:
                        progress_callback(completed_count, total_files, file_path)
                pool.shutdown(wait=True)
            except BaseException:
                _terminate_pool(pool, futures)
                raise
        return results
