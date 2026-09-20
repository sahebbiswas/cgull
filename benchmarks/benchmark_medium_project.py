#!/usr/bin/env python3
"""End-to-end medium-project scan benchmark with phase-level timing.

The workload is generated deterministically so results from different machines
and Python versions can be compared without downloading a third-party corpus.
The benchmark intentionally exercises multiple source files, nested shared
headers, cross-TU calls, project summaries, file/TU scan modes, and sequential
or multiprocessing execution.

Phase timings are benchmark-only instrumentation. Normal C-GULL scans do not
pay the monkeypatch/wrapper overhead used here.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import threading
from typing import Any, Iterator, Sequence

from cgull import CGullScanner, ScanConfig, ScanMode, __version__, telemetry_for
from cgull.ast_analyzer import CASTParser
from cgull.includes import IncludeResolver, TUIncludeExpander
from cgull import project_analysis
from cgull import parallel_workers

try:
    from benchmarks import benchmark_pass_metrics as pass_metrics
except ImportError:  # Direct execution places benchmarks/ itself on sys.path.
    import benchmark_pass_metrics as pass_metrics

_ORIGINAL_PREPARE_SOURCE = getattr(project_analysis, "_prepare_source", None)


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODULES = 16
DEFAULT_FUNCTIONS_PER_MODULE = 10
DEFAULT_STATEMENTS_PER_FUNCTION = 12
DEFAULT_JOBS = (1, 2, 4, 0)
DEFAULT_MODES = ("file", "tu")
DEFAULT_REPETITIONS = 1
WORKLOAD_PRESETS = {
    "standard": {
        "modules": DEFAULT_MODULES,
        "functions_per_module": DEFAULT_FUNCTIONS_PER_MODULE,
        "statements_per_function": DEFAULT_STATEMENTS_PER_FUNCTION,
    },
    "large": {
        "modules": 4,
        "functions_per_module": 160,
        "statements_per_function": DEFAULT_STATEMENTS_PER_FUNCTION,
    },
}


@dataclass
class PhaseRecorder:
    """Accumulate benchmark phase activity without touching production telemetry."""

    seconds: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    pass_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    pass_seconds: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    worker_pids: set[int] = field(default_factory=set)
    project_depth: int = 0

    def add(self, name: str, elapsed: float) -> None:
        self.seconds[name] += max(0.0, elapsed)

    def value(self, name: str) -> float:
        return float(self.seconds.get(name, 0.0))

    def add_pass(self, name: str, elapsed: float) -> None:
        self.pass_counts[name] += 1
        self.pass_seconds[name] += max(0.0, elapsed)

    def pass_snapshot(self) -> dict[str, dict[str, int | float]]:
        return {
            name: {
                "invocation_count": int(self.pass_counts.get(name, 0)),
                "inclusive_wall_seconds": float(self.pass_seconds.get(name, 0.0)),
            }
            for name in pass_metrics.PASS_NAMES
        }

    def merge_pass_metrics(self, snapshot: dict[str, dict[str, Any]]) -> None:
        for name in pass_metrics.PASS_NAMES:
            metric = snapshot.get(name, {})
            self.pass_counts[name] += int(metric.get("invocation_count", 0))
            self.pass_seconds[name] += max(
                0.0, float(metric.get("inclusive_wall_seconds", 0.0))
            )




_BENCHMARK_PREP_ARTIFACT_KEY = "__cgull_benchmark_prep_artifact__"


@dataclass
class _BenchmarkPrepArtifact:
    """Carry prep-worker benchmark metrics across IPC when no units exist."""

    seconds: dict[str, float]
    pass_metrics: dict[str, dict[str, int | float]]

@dataclass(frozen=True)
class SemanticSnapshot:
    findings: tuple[tuple[Any, ...], ...]
    parser_status_counts: tuple[tuple[str, int], ...]
    files_discovered: int
    files_analyzed: int
    files_ignored: int
    files_failed: int
    scan_errors: tuple[tuple[str, str, str], ...]


@dataclass(frozen=True)
class Sample:
    mode: str
    jobs: int
    repetition: int
    wall_seconds: float
    analyzed_lines: int
    unique_source_lines: int
    expanded_analysis_lines: int
    throughput_kloc_per_sec: float
    peak_rss_bytes: int | None
    phases: dict[str, float]
    finding_count: int
    parse_fallback_count: int
    semantic_digest: str
    semantics: SemanticSnapshot
    sampled_peak_tree_rss_bytes: int | None = None
    pass_metrics: dict[str, dict[str, int | float]] = field(default_factory=dict)
    pass_metric_worker_snapshots: int = 0
    pass_metric_expected_worker_snapshots: int = 0
    pass_metric_worker_snapshots_complete: bool = True


class BenchmarkScanner(CGullScanner):
    """Scanner subclass that times the production worker dispatch paths."""

    def __init__(self, recorder: PhaseRecorder, *args: Any, **kwargs: Any) -> None:
        self._benchmark_recorder = recorder
        super().__init__(*args, **kwargs)

    def _scan_files_sequential(self, *args: Any, **kwargs: Any):
        started = time.perf_counter()
        try:
            return super()._scan_files_sequential(*args, **kwargs)
        finally:
            self._benchmark_recorder.add(
                "worker_execution_wall_seconds", time.perf_counter() - started
            )

    def _scan_files_parallel(self, *args: Any, **kwargs: Any):
        started = time.perf_counter()
        try:
            return super()._scan_files_parallel(*args, **kwargs)
        finally:
            self._benchmark_recorder.add(
                "worker_execution_wall_seconds", time.perf_counter() - started
            )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _csv_jobs(value: str) -> tuple[int, ...]:
    try:
        jobs = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("jobs must be comma-separated integers") from exc
    if not jobs or any(job < 0 for job in jobs):
        raise argparse.ArgumentTypeError("jobs must contain non-negative integers")
    return jobs


def _csv_modes(value: str) -> tuple[str, ...]:
    modes = tuple(item.strip().lower() for item in value.split(",") if item.strip())
    if not modes or any(mode not in {"file", "tu"} for mode in modes):
        raise argparse.ArgumentTypeError("modes must contain only 'file' and/or 'tu'")
    return modes


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark representative end-to-end C-GULL medium-project scans",
    )
    parser.add_argument(
        "--preset",
        choices=tuple(WORKLOAD_PRESETS),
        default="standard",
        help="generated workload preset; explicit dimension flags override it",
    )
    parser.add_argument("--modules", type=_positive_int)
    parser.add_argument("--functions-per-module", type=_positive_int)
    parser.add_argument("--statements-per-function", type=_positive_int)
    parser.add_argument(
        "--jobs",
        type=_csv_jobs,
        default=DEFAULT_JOBS,
        help="comma-separated worker matrix, including 0 for auto",
    )
    parser.add_argument(
        "--modes",
        type=_csv_modes,
        default=DEFAULT_MODES,
        help="comma-separated scan modes: file,tu",
    )
    parser.add_argument(
        "--repetitions",
        type=_positive_int,
        default=DEFAULT_REPETITIONS,
    )
    parser.add_argument("--output", type=Path, help="write complete JSON artifact here")
    parser.add_argument(
        "--workspace",
        type=Path,
        help="use/create this workspace instead of a temporary directory",
    )
    parser.add_argument(
        "--keep-workspace",
        action="store_true",
        help="keep an automatically-created temporary workload for inspection",
    )
    parser.add_argument(
        "--no-enforce-parity",
        action="store_true",
        help="record semantic differences instead of failing the benchmark",
    )
    args = parser.parse_args(argv)
    preset = WORKLOAD_PRESETS[args.preset]
    for name, value in preset.items():
        if getattr(args, name) is None:
            setattr(args, name, value)
    return args


def generate_medium_project(
    root: Path,
    *,
    modules: int = DEFAULT_MODULES,
    functions_per_module: int = DEFAULT_FUNCTIONS_PER_MODULE,
    statements_per_function: int = DEFAULT_STATEMENTS_PER_FUNCTION,
) -> Path:
    """Create a deterministic multi-TU C project and return its project root."""

    project = root / "medium-project"
    if project.exists():
        shutil.rmtree(project)
    include_dir = project / "include"
    src_dir = project / "src"
    include_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    (include_dir / "bench_types.h").write_text(
        "#ifndef BENCH_TYPES_H\n"
        "#define BENCH_TYPES_H\n"
        "typedef struct bench_state { int value; int salt; } bench_state;\n"
        "static inline int bench_mix(int value, int salt) { return (value * 33) ^ salt; }\n"
        "#endif\n",
        encoding="utf-8",
    )

    declarations = [
        "#ifndef BENCH_API_H",
        "#define BENCH_API_H",
        '#include "bench_types.h"',
        "extern char *gets(char *);",
    ]
    declarations.extend(f"int module_{index:02d}_entry(int value);" for index in range(modules))
    declarations.extend(
        [
            "int benchmark_known_issue(char *buffer);",
            "#endif",
            "",
        ]
    )
    (include_dir / "bench_api.h").write_text("\n".join(declarations), encoding="utf-8")

    for module in range(modules):
        lines = ['#include "bench_api.h"', ""]
        for function in range(functions_per_module):
            name = f"module_{module:02d}_fn_{function:02d}"
            lines.append(f"static int {name}(int input) {{")
            lines.append(f"    int value = bench_mix(input, {module + function + 1});")
            for statement in range(statements_per_function):
                constant = (module + 1) * 17 + (function + 1) * 7 + statement
                lines.append(f"    value = (value + {constant}) ^ (value >> 1);")
            lines.append("    return value;")
            lines.append("}")
            lines.append("")

        lines.append(f"int module_{module:02d}_entry(int value) {{")
        lines.append("    bench_state state = { value, 17 };")
        for function in range(functions_per_module):
            lines.append(
                f"    state.value = module_{module:02d}_fn_{function:02d}(state.value + state.salt);"
            )
        if module > 0:
            lines.append(
                f"    state.value += module_{module - 1:02d}_entry(state.value & 255);"
            )
        lines.append("    return state.value;")
        lines.append("}")
        lines.append("")

        if module == modules - 1:
            lines.extend(
                [
                    "int benchmark_known_issue(char *buffer) {",
                    "    return gets(buffer) != 0;",
                    "}",
                    "",
                ]
            )

        (src_dir / f"module_{module:02d}.c").write_text(
            "\n".join(lines), encoding="utf-8"
        )

    return project


def workload_manifest(project: Path) -> dict[str, Any]:
    files = sorted(
        path for path in project.rglob("*") if path.is_file() and path.suffix in {".c", ".h"}
    )
    physical_lines = 0
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(project).as_posix()
        payload = path.read_bytes()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        physical_lines += len(payload.decode("utf-8").splitlines())
    return {
        "file_count": len(files),
        "physical_lines": physical_lines,
        "sha256": digest.hexdigest(),
    }


def expanded_analysis_lines(result: Any, *, config: ScanConfig) -> int:
    """Measure include-expanded volume for the roots the completed scan analyzed.

    This is deliberately computed after the timed scan. It describes the analysis
    volume without adding a second include-expansion pass to any phase timing or
    to the scan's peak-RSS sample.
    """

    total = 0
    target_root = Path(result.target_path)
    for summary in result.file_summaries:
        if summary.status == "failed":
            continue
        path = Path(summary.file_path)
        if not path.is_absolute():
            path = target_root / path
        source = path.read_text(encoding="utf-8", errors="replace")
        resolver = IncludeResolver(
            include_roots=config.include_roots,
            base_dir=str(path.resolve().parent),
        )
        expanded = TUIncludeExpander(
            resolver=resolver,
            defined_syms=config.defined_syms,
        ).expand(source, source_path=str(path))
        total += len(expanded.expanded_text.splitlines())
    return total


@contextmanager
def phase_instrumentation(
    recorder: PhaseRecorder,
    *,
    worker_metrics_dir: Path | None = None,
) -> Iterator[None]:
    """Time major scan activities while leaving production code unchanged."""

    import cgull.engine as engine
    import cgull.project_analysis as project_analysis

    original_walk = engine.os.walk
    original_expand = TUIncludeExpander.expand
    original_parse = CASTParser.parse
    original_units = project_analysis.prepare_units
    original_source = getattr(project_analysis, "_prepare_source", None)
    original_prepare = project_analysis.prepare_project
    original_index_init = project_analysis.ProjectSummaryIndex.__init__
    original_index_build = project_analysis.ProjectSummaryIndex.build
    original_scan_worker_item = parallel_workers._scan_worker_item
    original_build_parallel_work_item = parallel_workers.build_parallel_work_item
    original_process_pool_executor = parallel_workers.ProcessPoolExecutor
    pass_restorations = pass_metrics.install_pass_wrappers(recorder)
    previous_worker_metrics_dir = os.environ.get(pass_metrics.WORKER_METRICS_ENV)

    def timed_walk(*args: Any, **kwargs: Any):
        started = time.perf_counter()
        try:
            yield from original_walk(*args, **kwargs)
        finally:
            recorder.add("file_discovery_seconds", time.perf_counter() - started)

    def timed_expand(self: TUIncludeExpander, *args: Any, **kwargs: Any):
        started = time.perf_counter()
        try:
            return original_expand(self, *args, **kwargs)
        finally:
            prefix = "project" if recorder.project_depth else "scan"
            recorder.add(
                f"{prefix}_tu_include_expansion_seconds",
                time.perf_counter() - started,
            )

    def timed_parse(self: CASTParser, *args: Any, **kwargs: Any):
        started = time.perf_counter()
        try:
            return original_parse(self, *args, **kwargs)
        finally:
            prefix = "project" if recorder.project_depth else "scan"
            recorder.add(f"{prefix}_parser_seconds", time.perf_counter() - started)

    def timed_prepare(*args: Any, **kwargs: Any):
        recorder.project_depth += 1
        started = time.perf_counter()
        try:
            return original_prepare(*args, **kwargs)
        finally:
            recorder.add(
                "project_preparation_seconds", time.perf_counter() - started
            )
            recorder.project_depth -= 1
            recorder.add("preparation_wall_seconds", time.perf_counter() - started)

    def timed_units(*args: Any, **kwargs: Any):
        started = time.perf_counter()
        recorder.project_depth += 1
        try:
            units, errors = original_units(*args, **kwargs)
            cleaned: dict[str, dict[str, Any]] = {}
            for path, values in units.items():
                kept: dict[str, Any] = {}
                for key, unit in values.items():
                    if isinstance(unit, _BenchmarkPrepArtifact) or key == _BENCHMARK_PREP_ARTIFACT_KEY:
                        for name, elapsed in unit.seconds.items():
                            recorder.add(name, elapsed)
                        recorder.merge_pass_metrics(unit.pass_metrics)
                        continue
                    for name, elapsed in getattr(unit, "_benchmark_seconds", {}).items():
                        recorder.add(name, elapsed)
                    if hasattr(unit, "_benchmark_seconds"):
                        del unit._benchmark_seconds
                    benchmark_passes = getattr(unit, "_benchmark_pass_metrics", None)
                    if benchmark_passes:
                        recorder.merge_pass_metrics(benchmark_passes)
                    if hasattr(unit, "_benchmark_pass_metrics"):
                        del unit._benchmark_pass_metrics
                    kept[key] = unit
                cleaned[path] = kept
            return cleaned, errors
        finally:
            recorder.add("independent_preparation_seconds", time.perf_counter() - started)
            recorder.project_depth -= 1
            if recorder.project_depth == 0:
                recorder.add("preparation_wall_seconds", time.perf_counter() - started)

    def timed_index_init(self: Any, *args: Any, **kwargs: Any) -> None:
        started = time.perf_counter()
        try:
            original_index_init(self, *args, **kwargs)
        finally:
            recorder.add("project_indexing_seconds", time.perf_counter() - started)

    def timed_index_build(self: Any, *args: Any, **kwargs: Any):
        started = time.perf_counter()
        try:
            return original_index_build(self, *args, **kwargs)
        finally:
            recorder.add(
                "project_summary_construction_seconds",
                time.perf_counter() - started,
            )

    def benchmark_build_parallel_work_item(*args: Any, **kwargs: Any):
        item = original_build_parallel_work_item(*args, **kwargs)
        if worker_metrics_dir is None:
            return item
        return pass_metrics.attach_worker_metrics_dir(item, worker_metrics_dir)

    class BenchmarkProcessPoolExecutor(original_process_pool_executor):
        """Record the worker processes the production executor actually created."""

        def shutdown(self, *args: Any, **kwargs: Any):
            processes = getattr(self, "_processes", None) or {}
            recorder.worker_pids.update(int(pid) for pid in processes)
            return super().shutdown(*args, **kwargs)

    engine.os.walk = timed_walk
    TUIncludeExpander.expand = timed_expand
    CASTParser.parse = timed_parse
    project_analysis.prepare_units = timed_units
    if original_source is not None:
        project_analysis._prepare_source = _timed_prepare_source
    project_analysis.prepare_project = timed_prepare
    project_analysis.ProjectSummaryIndex.__init__ = timed_index_init
    project_analysis.ProjectSummaryIndex.build = timed_index_build
    if worker_metrics_dir is not None:
        os.environ[pass_metrics.WORKER_METRICS_ENV] = str(worker_metrics_dir)
        parallel_workers.build_parallel_work_item = benchmark_build_parallel_work_item
        parallel_workers.ProcessPoolExecutor = BenchmarkProcessPoolExecutor
        parallel_workers._scan_worker_item = pass_metrics.benchmark_scan_worker_item
    try:
        yield
    finally:
        engine.os.walk = original_walk
        TUIncludeExpander.expand = original_expand
        CASTParser.parse = original_parse
        project_analysis.prepare_units = original_units
        if original_source is not None:
            project_analysis._prepare_source = original_source
        project_analysis.prepare_project = original_prepare
        project_analysis.ProjectSummaryIndex.__init__ = original_index_init
        project_analysis.ProjectSummaryIndex.build = original_index_build
        parallel_workers._scan_worker_item = original_scan_worker_item
        parallel_workers.build_parallel_work_item = original_build_parallel_work_item
        parallel_workers.ProcessPoolExecutor = original_process_pool_executor
        if previous_worker_metrics_dir is None:
            os.environ.pop(pass_metrics.WORKER_METRICS_ENV, None)
        else:
            os.environ[pass_metrics.WORKER_METRICS_ENV] = previous_worker_metrics_dir
        pass_metrics.restore_pass_wrappers(pass_restorations)


def _prep_metrics_worth_keeping(
    seconds: dict[str, float],
    snapshot: dict[str, dict[str, int | float]],
) -> bool:
    if any(float(value) > 0.0 for value in seconds.values()):
        return True
    return any(
        int(metric.get("invocation_count", 0)) > 0
        or float(metric.get("inclusive_wall_seconds", 0.0)) > 0.0
        for metric in snapshot.values()
    )


def _timed_prepare_source(*args):
    """Benchmark-only process entry point, including spawn on Windows/macOS."""
    seconds = defaultdict(float)
    worker_passes = pass_metrics.PassRecorder()
    pass_restorations = pass_metrics.install_pass_wrappers(worker_passes)
    original_parse = CASTParser.parse
    original_expand = TUIncludeExpander.expand

    def parse(*a, **kw):
        started = time.perf_counter()
        try:
            return original_parse(*a, **kw)
        finally:
            seconds["project_parser_seconds"] += time.perf_counter() - started

    def expand(*a, **kw):
        started = time.perf_counter()
        try:
            return original_expand(*a, **kw)
        finally:
            seconds["project_tu_include_expansion_seconds"] += time.perf_counter() - started

    CASTParser.parse, TUIncludeExpander.expand = parse, expand
    try:
        units, errors = _ORIGINAL_PREPARE_SOURCE(*args)
        seconds_dict = dict(seconds)
        pass_snapshot = worker_passes.snapshot()
        if units:
            unit = next(iter(units.values()))
            unit._benchmark_seconds = seconds_dict
            unit._benchmark_pass_metrics = pass_snapshot
        elif _prep_metrics_worth_keeping(seconds_dict, pass_snapshot):
            # Keep observational metrics even when preparation produced no units.
            units = {
                _BENCHMARK_PREP_ARTIFACT_KEY: _BenchmarkPrepArtifact(
                    seconds_dict,
                    pass_snapshot,
                )
            }
        return units, errors
    finally:
        CASTParser.parse, TUIncludeExpander.expand = original_parse, original_expand
        pass_metrics.restore_pass_wrappers(pass_restorations)


@contextmanager
def sample_tree_memory():
    """Optional psutil sampling of coordinator plus live descendant RSS."""
    peak = [None]
    try:
        import psutil
    except ImportError:
        yield peak
        return
    # /proc may be mounted from an outer PID namespace. Resolve the PID as
    # seen by that mount, rather than accidentally sampling an unrelated PID 2.
    process_pid = os.getpid()
    if sys.platform.startswith("linux"):
        try:
            process_pid = int(Path("/proc/self/stat").read_text().split()[0])
        except (OSError, ValueError):
            pass
    process = psutil.Process(process_pid)
    stop = threading.Event()

    def sample():
        while not stop.is_set():
            total = 0
            for item in [process, *process.children(recursive=True)]:
                try:
                    total += item.memory_info().rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            peak[0] = max(peak[0] or 0, total)
            stop.wait(0.01)

    thread = threading.Thread(target=sample, daemon=True)
    thread.start()
    try:
        yield peak
    finally:
        stop.set()
        thread.join()


def _peak_rss_bytes() -> int | None:
    try:
        import resource

        rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except (ImportError, OSError, ValueError):
        return None
    if sys.platform == "darwin":
        return rss
    return rss * 1024


def _revision() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return completed.stdout.strip() or "unknown"


def _semantic_snapshot(result: Any) -> SemanticSnapshot:
    findings = tuple(
        sorted(
            (
                issue.fingerprint or "",
                issue.rule_id,
                str(issue.file_path).replace("\\", "/"),
                int(issue.line_number),
                int(issue.column_number),
                issue.message,
            )
            for issue in result.issues
        )
    )
    errors = tuple(
        sorted((error.file_path, error.error_type, error.message) for error in result.scan_errors)
    )
    return SemanticSnapshot(
        findings=findings,
        parser_status_counts=tuple(sorted(result.analysis_status_counts.items())),
        files_discovered=int(result.files_discovered),
        files_analyzed=int(result.files_analyzed),
        files_ignored=int(result.files_ignored),
        files_failed=int(result.files_failed),
        scan_errors=errors,
    )


def _semantic_digest(snapshot: SemanticSnapshot) -> str:
    payload = json.dumps(asdict(snapshot), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _phase_output(
    recorder: PhaseRecorder,
    *,
    result: Any,
    jobs: int,
    wall_seconds: float,
) -> dict[str, float]:
    summaries = list(result.file_summaries)
    aggregate_file_seconds = sum(summary.scan_duration_ms for summary in summaries) / 1000.0
    maximum_file_seconds = max(
        (summary.scan_duration_ms for summary in summaries), default=0.0
    ) / 1000.0
    resolved_jobs = (os.cpu_count() or 1) if jobs == 0 else max(1, jobs)
    resolved_jobs = min(resolved_jobs, max(1, len(summaries)))
    ideal_parallel_compute = max(
        maximum_file_seconds,
        aggregate_file_seconds / max(1, resolved_jobs),
    )
    worker_wall = recorder.value("worker_execution_wall_seconds")
    worker_residual = max(0.0, worker_wall - ideal_parallel_compute)
    parser_seconds = recorder.value("project_parser_seconds") + recorder.value(
        "scan_parser_seconds"
    )
    expansion_seconds = recorder.value(
        "project_tu_include_expansion_seconds"
    ) + recorder.value("scan_tu_include_expansion_seconds")
    rule_execution = max(
        0.0,
        aggregate_file_seconds
        - recorder.value("scan_parser_seconds")
        - recorder.value("scan_tu_include_expansion_seconds"),
    )

    return {
        "file_discovery_seconds": recorder.value("file_discovery_seconds"),
        "tu_include_expansion_seconds": expansion_seconds,
        "parser_seconds": parser_seconds,
        "project_preparation_seconds": recorder.value("project_preparation_seconds"),
        "preparation_wall_seconds": recorder.value("preparation_wall_seconds"),
        "independent_preparation_seconds": recorder.value("independent_preparation_seconds"),
        "project_indexing_seconds": recorder.value("project_indexing_seconds"),
        "project_summary_construction_seconds": recorder.value(
            "project_summary_construction_seconds"
        ),
        "rule_execution_aggregate_seconds": rule_execution,
        "worker_execution_wall_seconds": worker_wall,
        "worker_startup_ipc_collection_residual_seconds": worker_residual,
        "aggregate_file_analysis_seconds": aggregate_file_seconds,
        "total_wall_seconds": wall_seconds,
    }


def run_sample(project: Path, *, mode: str, jobs: int, repetition: int) -> Sample:
    recorder = PhaseRecorder()
    config = ScanConfig.create(
        mode=ScanMode(mode),
        include_roots=[str(project / "include")],
    )
    scanner = BenchmarkScanner(recorder, config=config)
    with tempfile.TemporaryDirectory(prefix="cgull-pass-metrics-") as metrics_tmp:
        worker_metrics_dir = Path(metrics_tmp)
        with sample_tree_memory() as tree_peak, phase_instrumentation(
            recorder, worker_metrics_dir=worker_metrics_dir
        ):
            started = time.perf_counter()
            result = scanner.scan_path(str(project), jobs=jobs, quiet=True)
            wall_seconds = max(1e-9, time.perf_counter() - started)
        worker_metric_snapshots = pass_metrics.merge_worker_metric_files(
            recorder, worker_metrics_dir
        )

    peak_rss = _peak_rss_bytes()
    expanded_lines = expanded_analysis_lines(result, config=config)
    telemetry = telemetry_for(result)
    snapshot = _semantic_snapshot(result)
    expected_worker_metric_snapshots = len(recorder.worker_pids)
    return Sample(
        mode=mode,
        jobs=jobs,
        repetition=repetition,
        wall_seconds=wall_seconds,
        analyzed_lines=telemetry.analyzed_lines,
        unique_source_lines=telemetry.unique_source_lines,
        expanded_analysis_lines=expanded_lines,
        throughput_kloc_per_sec=(telemetry.analyzed_lines / 1000.0) / wall_seconds
        if telemetry.analyzed_lines
        else 0.0,
        peak_rss_bytes=peak_rss,
        sampled_peak_tree_rss_bytes=tree_peak[0],
        phases=_phase_output(
            recorder,
            result=result,
            jobs=jobs,
            wall_seconds=wall_seconds,
        ),
        finding_count=result.total_issues_count,
        parse_fallback_count=telemetry.parse_fallback_count,
        semantic_digest=_semantic_digest(snapshot),
        semantics=snapshot,
        pass_metrics=recorder.pass_snapshot(),
        pass_metric_worker_snapshots=worker_metric_snapshots,
        pass_metric_expected_worker_snapshots=expected_worker_metric_snapshots,
        pass_metric_worker_snapshots_complete=(
            worker_metric_snapshots == expected_worker_metric_snapshots
        ),
    )


def validate_parity(samples: Sequence[Sample]) -> dict[str, Any]:
    """Require jobs/repetitions to preserve semantics within each scan mode."""

    differences: list[str] = []
    by_mode: dict[str, list[Sample]] = defaultdict(list)
    for sample in samples:
        by_mode[sample.mode].append(sample)

    for mode, mode_samples in sorted(by_mode.items()):
        reference = mode_samples[0]
        for sample in mode_samples[1:]:
            if sample.semantics != reference.semantics:
                differences.append(
                    f"{mode}: jobs={sample.jobs} repetition={sample.repetition} "
                    f"differs from jobs={reference.jobs} repetition={reference.repetition}"
                )
            if sample.expanded_analysis_lines != reference.expanded_analysis_lines:
                differences.append(
                    f"{mode}: jobs={sample.jobs} repetition={sample.repetition} "
                    "produced different expanded analysis volume"
                )

    cross_mode_findings_match = True
    if len(by_mode) > 1:
        representatives = [mode_samples[0] for _, mode_samples in sorted(by_mode.items())]
        first_findings = representatives[0].semantics.findings
        cross_mode_findings_match = all(
            sample.semantics.findings == first_findings for sample in representatives[1:]
        )
        if not cross_mode_findings_match:
            differences.append("file and TU modes produced different findings/fingerprints")
            baseline_mode = sorted(by_mode)[0]
            baseline_findings = Counter(by_mode[baseline_mode][0].semantics.findings)
            for mode in sorted(by_mode)[1:]:
                mode_findings = Counter(by_mode[mode][0].semantics.findings)
                missing = list((baseline_findings - mode_findings).elements())[:5]
                extra = list((mode_findings - baseline_findings).elements())[:5]
                if missing:
                    differences.append(
                        f"{mode} missing findings present in {baseline_mode}: {missing}"
                    )
                if extra:
                    differences.append(
                        f"{mode} extra findings vs {baseline_mode}: {extra}"
                    )

    return {
        "passes": not differences,
        "within_mode_jobs_and_repetitions_match": not any(
            not difference.startswith("file and TU") for difference in differences
        ),
        "cross_mode_findings_match": cross_mode_findings_match,
        "differences": differences,
    }


def summarize(
    samples: Sequence[Sample],
    *,
    generated_function_count: int | None = None,
) -> dict[str, Any]:
    groups: dict[tuple[str, int], list[Sample]] = defaultdict(list)
    for sample in samples:
        groups[(sample.mode, sample.jobs)].append(sample)

    arms: dict[str, Any] = {}
    for (mode, jobs), group in sorted(groups.items()):
        key = f"{mode}/jobs={jobs}"
        arms[key] = {
            "mode": mode,
            "jobs": jobs,
            "samples": len(group),
            "expanded_analysis_lines": group[0].expanded_analysis_lines,
            "median_wall_seconds": statistics.median(s.wall_seconds for s in group),
            "median_throughput_kloc_per_sec": statistics.median(
                s.throughput_kloc_per_sec for s in group
            ),
            "median_phases_seconds": {
                name: statistics.median(s.phases[name] for s in group)
                for name in group[0].phases
            },
            "worker_pass_metric_snapshots": {
                "minimum_merged": min(
                    s.pass_metric_worker_snapshots for s in group
                ),
                "expected": group[0].pass_metric_expected_worker_snapshots,
                "all_complete": all(
                    s.pass_metric_worker_snapshots_complete for s in group
                ),
            },
            "median_pass_metrics": {
                name: {
                    "median_invocation_count": statistics.median(
                        int(s.pass_metrics.get(name, {}).get("invocation_count", 0))
                        for s in group
                    ),
                    "median_inclusive_wall_seconds": statistics.median(
                        float(
                            s.pass_metrics.get(name, {}).get(
                                "inclusive_wall_seconds", 0.0
                            )
                        )
                        for s in group
                    ),
                    "median_calls_per_analyzed_file": statistics.median(
                        int(s.pass_metrics.get(name, {}).get("invocation_count", 0))
                        / max(1, s.semantics.files_analyzed)
                        for s in group
                    ),
                    "median_calls_per_generated_function": (
                        statistics.median(
                            int(
                                s.pass_metrics.get(name, {}).get(
                                    "invocation_count", 0
                                )
                            )
                            / generated_function_count
                            for s in group
                        )
                        if generated_function_count
                        else None
                    ),
                }
                for name in pass_metrics.PASS_NAMES
            },
        }
    return {"arms": arms}


def _generated_function_count(*, modules: int, functions_per_module: int) -> int:
    # One entry point per module plus the generated helpers, bench_mix(), and
    # benchmark_known_issue(). This is a unique-source-definition denominator;
    # TU expansion may analyze header functions more than once.
    return modules * (functions_per_module + 1) + 2


def build_artifact(
    project: Path,
    *,
    samples: Sequence[Sample],
    args: argparse.Namespace,
) -> dict[str, Any]:
    generated_function_count = _generated_function_count(
        modules=args.modules,
        functions_per_module=args.functions_per_module,
    )
    return {
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": sys.version,
            "python_executable": sys.executable,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "cgull_version": __version__,
            "cgull_revision": _revision(),
        },
        "workload": {
            **workload_manifest(project),
            "modules": args.modules,
            "functions_per_module": args.functions_per_module,
            "statements_per_function": args.statements_per_function,
            "generated_function_count": generated_function_count,
        },
        "configuration": {
            "preset": args.preset,
            "modes": list(args.modes),
            "jobs": list(args.jobs),
            "repetitions": args.repetitions,
            "rules": "default",
        },
        "parity": validate_parity(samples),
        "summary": summarize(
            samples, generated_function_count=generated_function_count
        ),
        "samples": [
            {
                **asdict(sample),
                "semantics": asdict(sample.semantics),
            }
            for sample in samples
        ],
        "timing_notes": {
            "activity_timings_overlap": True,
            "rule_execution_aggregate_seconds": (
                "sum of per-file analysis durations minus scan-local parser/include work; "
                "it is CPU-like aggregate work and may exceed wall time in parallel mode"
            ),
            "worker_startup_ipc_collection_residual_seconds": (
                "worker-dispatch wall time minus a conservative ideal-compute lower bound; "
                "use for relative before/after comparisons on the same machine"
            ),
            "peak_rss_bytes": (
                "process-lifetime ru_maxrss sampled immediately after scan_path; null where "
                "the platform does not expose it"
            ),
            "expanded_analysis_lines": (
                "include-expanded line volume recomputed after the timed scan for exactly "
                "the analyzed roots; excluded from scan timing and peak-RSS measurement"
            ),
            "pass_metrics": (
                "benchmark-only invocation counts and inclusive wall activity for repeated "
                "CFG/event/summary/preprocessor passes; parallel-worker activity is merged "
                "into the coordinator artifact, timings overlap, and must not be summed"
            ),
            "pass_metric_worker_snapshots": (
                "parallel workers flush cumulative snapshots before each Future resolves; "
                "merged/expected/completeness fields expose hard-process losses that could "
                "otherwise undercount a benchmark arm"
            ),
        },
    }


def _print_summary(artifact: dict[str, Any]) -> None:
    print("C-GULL medium-project benchmark")
    print(
        f"workload: {artifact['workload']['file_count']} files, "
        f"{artifact['workload']['physical_lines']} physical LOC"
    )
    for name, arm in artifact["summary"]["arms"].items():
        print(
            f"{name:16s}  {arm['median_wall_seconds']:.3f}s  "
            f"{arm['median_throughput_kloc_per_sec']:.3f} KLOC/s  "
            f"expanded={arm['expanded_analysis_lines']} lines"
        )
        rendered_passes = ", ".join(
            f"{pass_name}={metric['median_invocation_count']:g}x/"
            f"{metric['median_inclusive_wall_seconds']:.3f}s"
            for pass_name, metric in arm["median_pass_metrics"].items()
        )
        print(f"  passes: {rendered_passes}")
        snapshots = arm["worker_pass_metric_snapshots"]
        if snapshots["expected"]:
            print(
                "  worker snapshots: "
                f"{snapshots['minimum_merged']}/{snapshots['expected']} "
                f"({'complete' if snapshots['all_complete'] else 'INCOMPLETE'})"
            )
    parity = artifact["parity"]
    print(f"semantic parity: {'PASS' if parity['passes'] else 'FAIL'}")
    for difference in parity["differences"]:
        print(f"  - {difference}")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    owned_temp: tempfile.TemporaryDirectory[str] | None = None
    if args.workspace is not None:
        workspace = args.workspace.resolve()
        workspace.mkdir(parents=True, exist_ok=True)
    else:
        owned_temp = tempfile.TemporaryDirectory(prefix="cgull-medium-benchmark-")
        workspace = Path(owned_temp.name)

    try:
        project = generate_medium_project(
            workspace,
            modules=args.modules,
            functions_per_module=args.functions_per_module,
            statements_per_function=args.statements_per_function,
        )
        samples = [
            run_sample(project, mode=mode, jobs=jobs, repetition=repetition)
            for repetition in range(args.repetitions)
            for mode in args.modes
            for jobs in args.jobs
        ]
        artifact = build_artifact(project, samples=samples, args=args)
        _print_summary(artifact)
        payload = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload, encoding="utf-8")
            print(f"JSON artifact: {args.output}")
        elif not sys.stdout.isatty():
            print(payload, end="")
        if not artifact["parity"]["passes"] and not args.no_enforce_parity:
            return 2
        return 0
    finally:
        if owned_temp is not None:
            if args.keep_workspace:
                # TemporaryDirectory cleanup is explicit so keeping the workload
                # does not depend on interpreter shutdown behavior.
                kept = Path(tempfile.mkdtemp(prefix="cgull-medium-benchmark-kept-"))
                shutil.copytree(workspace, kept / "workspace", dirs_exist_ok=True)
                print(f"kept workspace: {kept / 'workspace'}")
            owned_temp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
