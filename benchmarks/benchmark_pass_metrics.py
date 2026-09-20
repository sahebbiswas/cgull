"""Benchmark-local instrumentation for repeated analysis passes.

This module intentionally lives under benchmarks/. Production scans never import
or execute these wrappers. It is separate from benchmark_medium_project.py so
ProcessPoolExecutor spawn workers can import the worker entry point by module
name and report their local counters back to the benchmark coordinator.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from functools import wraps
import json
import multiprocessing.util
import os
from pathlib import Path
import sys
import time
from typing import Any

from cgull import parallel_workers
from cgull.cfg import construction as cfg_construction
from cgull.cfg import summaries as cfg_summaries
from cgull.preprocessor import directives as preprocessor_directives


PASS_NAMES = (
    "build_cfg",
    "apply_cfg_event_semantics",
    "clone_structural_cfg",
    "analyze_function_summaries_detailed",
    "parse_conditional_directives",
)
WORKER_METRICS_ENV = "CGULL_BENCHMARK_PASS_METRICS_DIR"

_TARGETS = {
    "build_cfg": cfg_construction.build_cfg,
    "apply_cfg_event_semantics": cfg_construction.apply_cfg_event_semantics,
    "clone_structural_cfg": cfg_construction.clone_structural_cfg,
    "analyze_function_summaries_detailed": cfg_summaries.analyze_function_summaries_detailed,
    "parse_conditional_directives": preprocessor_directives.parse_conditional_directives,
}
_ORIGINAL_SCAN_WORKER_ITEM = parallel_workers._scan_worker_item


@dataclass
class PassRecorder:
    """Accumulate count and inclusive wall time for benchmark-only pass wrappers."""

    counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    seconds: dict[str, float] = field(default_factory=lambda: defaultdict(float))

    def add_pass(self, name: str, elapsed: float) -> None:
        self.counts[name] += 1
        self.seconds[name] += max(0.0, elapsed)

    def snapshot(self) -> dict[str, dict[str, int | float]]:
        return {
            name: {
                "invocation_count": int(self.counts.get(name, 0)),
                "inclusive_wall_seconds": float(self.seconds.get(name, 0.0)),
            }
            for name in PASS_NAMES
        }

    def merge(self, snapshot: dict[str, dict[str, Any]]) -> None:
        for name in PASS_NAMES:
            metric = snapshot.get(name, {})
            self.counts[name] += int(metric.get("invocation_count", 0))
            self.seconds[name] += max(
                0.0, float(metric.get("inclusive_wall_seconds", 0.0))
            )


def _make_wrapper(name: str, original: Any, recorder: Any):
    @wraps(original)
    def timed(*args: Any, **kwargs: Any):
        started = time.perf_counter()
        try:
            return original(*args, **kwargs)
        finally:
            recorder.add_pass(name, time.perf_counter() - started)

    timed._cgull_benchmark_pass_original = original
    return timed


def install_pass_wrappers(recorder: Any) -> list[tuple[Any, str, Any]]:
    """Patch defining functions and already-imported aliases inside cgull modules."""

    wrappers = {
        name: _make_wrapper(name, original, recorder)
        for name, original in _TARGETS.items()
    }
    restorations: list[tuple[Any, str, Any]] = []

    for module in list(sys.modules.values()):
        module_name = getattr(module, "__name__", "")
        if not module_name.startswith("cgull"):
            continue
        try:
            namespace = list(vars(module).items())
        except TypeError:
            continue
        for attribute, value in namespace:
            for name, original in _TARGETS.items():
                wrapped_original = getattr(
                    value, "_cgull_benchmark_pass_original", None
                )
                if value is not original and wrapped_original is not original:
                    continue
                restorations.append((module, attribute, value))
                setattr(module, attribute, wrappers[name])
                break

    return restorations


def restore_pass_wrappers(restorations: list[tuple[Any, str, Any]]) -> None:
    for module, attribute, value in reversed(restorations):
        setattr(module, attribute, value)


_WORKER_RECORDER: PassRecorder | None = None
_WORKER_PID: int | None = None
_WORKER_METRICS_DIR: str | None = None
_WORKER_RESTORATIONS: list[tuple[Any, str, Any]] = []
_WORKER_FINALIZER: Any = None


def _flush_worker_metrics() -> None:
    if _WORKER_RECORDER is None or _WORKER_METRICS_DIR is None:
        return
    directory = Path(_WORKER_METRICS_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{os.getpid()}.json"
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(_WORKER_RECORDER.snapshot(), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, destination)


def _ensure_worker_instrumentation() -> None:
    global _WORKER_FINALIZER
    global _WORKER_METRICS_DIR
    global _WORKER_PID
    global _WORKER_RECORDER
    global _WORKER_RESTORATIONS

    metrics_dir = os.environ.get(WORKER_METRICS_ENV)
    if not metrics_dir:
        return

    pid = os.getpid()
    if (
        _WORKER_RECORDER is not None
        and _WORKER_PID == pid
        and _WORKER_METRICS_DIR == metrics_dir
    ):
        return

    # The current scanner creates and shuts down its ProcessPoolExecutor inside
    # each scan sample, so the worker finalizer normally runs before the
    # coordinator merges metric files. Preserve the previous snapshot as well
    # if workers ever become reusable across samples and the destination changes.
    if (
        _WORKER_RECORDER is not None
        and _WORKER_PID == pid
        and _WORKER_METRICS_DIR is not None
        and _WORKER_METRICS_DIR != metrics_dir
    ):
        _flush_worker_metrics()

    if _WORKER_RESTORATIONS:
        restore_pass_wrappers(_WORKER_RESTORATIONS)

    _WORKER_PID = pid
    _WORKER_METRICS_DIR = metrics_dir
    _WORKER_RECORDER = PassRecorder()
    _WORKER_RESTORATIONS = install_pass_wrappers(_WORKER_RECORDER)
    _WORKER_FINALIZER = multiprocessing.util.Finalize(
        None, _flush_worker_metrics, exitpriority=0
    )


def benchmark_scan_worker_item(item: Any):
    """Process-pool entry point that adds pass metrics without changing its result."""

    _ensure_worker_instrumentation()
    try:
        return _ORIGINAL_SCAN_WORKER_ITEM(item)
    finally:
        # Persist the cumulative snapshot before this task's Future is resolved.
        # This also records Python-level worker failures that the coordinator
        # converts into ordinary scan errors. A hard process kill can still
        # prevent this write, which the benchmark exposes via snapshot counts.
        _flush_worker_metrics()


def merge_worker_metric_files(recorder: Any, directory: Path) -> int:
    """Merge one final cumulative snapshot per worker process.

    ParallelWorkerMixin shuts its executor down with wait=True before returning,
    so worker finalizers have completed before the benchmark calls this function.
    The directory-switch flush above also preserves snapshots if that worker
    lifecycle changes in the future.
    """

    merged = 0
    for path in sorted(directory.glob("*.json")):
        snapshot = json.loads(path.read_text(encoding="utf-8"))
        if hasattr(recorder, "merge_pass_metrics"):
            recorder.merge_pass_metrics(snapshot)
        else:
            recorder.merge(snapshot)
        merged += 1
    return merged
