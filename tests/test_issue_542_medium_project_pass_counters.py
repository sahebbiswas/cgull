from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

from cgull.cfg import construction as cfg_construction
from cgull import parallel_workers


MODULE_PATH = Path(__file__).parents[1] / "benchmarks" / "benchmark_medium_project.py"
SPEC = importlib.util.spec_from_file_location("benchmark_medium_project_542", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


def test_large_workload_preset_is_deterministic_and_overridable():
    args = benchmark.parse_args(["--preset", "large", "--jobs", "1"])
    assert args.modules == 4
    assert args.functions_per_module == 160
    assert args.statements_per_function == benchmark.DEFAULT_STATEMENTS_PER_FUNCTION

    overridden = benchmark.parse_args(
        [
            "--preset",
            "large",
            "--modules",
            "3",
            "--functions-per-module",
            "7",
            "--statements-per-function",
            "5",
        ]
    )
    assert overridden.modules == 3
    assert overridden.functions_per_module == 7
    assert overridden.statements_per_function == 5


def test_pass_instrumentation_restores_all_wrappers_after_failure(tmp_path, monkeypatch):
    monkeypatch.delenv(benchmark.pass_metrics.WORKER_METRICS_ENV, raising=False)
    recorder = benchmark.PhaseRecorder()
    original_build_cfg = cfg_construction.build_cfg
    original_worker_item = parallel_workers._scan_worker_item
    original_work_item_builder = parallel_workers.build_parallel_work_item
    original_executor = parallel_workers.ProcessPoolExecutor

    with pytest.raises(RuntimeError, match="boom"):
        with benchmark.phase_instrumentation(
            recorder, worker_metrics_dir=tmp_path
        ):
            assert cfg_construction.build_cfg is not original_build_cfg
            assert parallel_workers._scan_worker_item is not original_worker_item
            assert parallel_workers.build_parallel_work_item is not original_work_item_builder
            assert parallel_workers.ProcessPoolExecutor is not original_executor
            raise RuntimeError("boom")

    assert cfg_construction.build_cfg is original_build_cfg
    assert parallel_workers._scan_worker_item is original_worker_item
    assert parallel_workers.build_parallel_work_item is original_work_item_builder
    assert parallel_workers.ProcessPoolExecutor is original_executor
    assert benchmark.pass_metrics.WORKER_METRICS_ENV not in benchmark.os.environ


def test_tiny_sample_reports_all_requested_pass_counters(tmp_path):
    project = benchmark.generate_medium_project(
        tmp_path,
        modules=2,
        functions_per_module=1,
        statements_per_function=1,
    )

    sample = benchmark.run_sample(project, mode="tu", jobs=1, repetition=0)

    assert tuple(sample.pass_metrics) == benchmark.pass_metrics.PASS_NAMES
    for metric in sample.pass_metrics.values():
        assert metric["invocation_count"] >= 0
        assert metric["inclusive_wall_seconds"] >= 0.0
    assert sample.pass_metrics["build_cfg"]["invocation_count"] > 0
    assert sample.semantics.files_failed == 0


def test_summary_reports_pass_medians_and_redundancy_ratios():
    semantics = benchmark.SemanticSnapshot(
        findings=(),
        parser_status_counts=(("pycparser_success", 2),),
        files_discovered=2,
        files_analyzed=2,
        files_ignored=0,
        files_failed=0,
        scan_errors=(),
    )
    pass_metrics = {
        name: {
            "invocation_count": 20 if name == "build_cfg" else 4,
            "inclusive_wall_seconds": 2.0 if name == "build_cfg" else 0.4,
        }
        for name in benchmark.pass_metrics.PASS_NAMES
    }
    sample = benchmark.Sample(
        mode="tu",
        jobs=1,
        repetition=0,
        wall_seconds=3.0,
        analyzed_lines=1000,
        unique_source_lines=1000,
        expanded_analysis_lines=1200,
        throughput_kloc_per_sec=1.0 / 3.0,
        peak_rss_bytes=None,
        phases={"total_wall_seconds": 3.0},
        finding_count=0,
        parse_fallback_count=0,
        semantic_digest="digest",
        semantics=semantics,
        pass_metrics=pass_metrics,
    )

    result = benchmark.summarize([sample], generated_function_count=5)
    metric = result["arms"]["tu/jobs=1"]["median_pass_metrics"]["build_cfg"]

    assert metric["median_invocation_count"] == 20
    assert metric["median_inclusive_wall_seconds"] == 2.0
    assert metric["median_calls_per_analyzed_file"] == 10.0
    assert metric["median_calls_per_generated_function"] == 4.0


def test_executor_tracker_counts_only_workers_actually_created(tmp_path, monkeypatch):
    class FakeExecutor:
        def __init__(self, *args, **kwargs):
            self._processes = {101: object()}

        def shutdown(self, *args, **kwargs):
            return "shutdown"

    monkeypatch.setattr(parallel_workers, "ProcessPoolExecutor", FakeExecutor)
    recorder = benchmark.PhaseRecorder()

    with benchmark.phase_instrumentation(recorder, worker_metrics_dir=tmp_path):
        executor = parallel_workers.ProcessPoolExecutor(max_workers=8)
        assert executor.shutdown(wait=True) == "shutdown"

    assert recorder.worker_pids == {101}
    assert parallel_workers.ProcessPoolExecutor is FakeExecutor


def test_worker_metric_directory_switch_flushes_previous_snapshot(tmp_path, monkeypatch):
    metrics = benchmark.pass_metrics
    first = tmp_path / "first"
    second = tmp_path / "second"
    recorder = metrics.PassRecorder()
    recorder.add_pass("build_cfg", 0.25)

    monkeypatch.setattr(metrics, "_WORKER_RECORDER", recorder)
    monkeypatch.setattr(metrics, "_WORKER_PID", os.getpid())
    monkeypatch.setattr(metrics, "_WORKER_METRICS_DIR", str(first))
    monkeypatch.setattr(metrics, "_WORKER_RESTORATIONS", [])
    monkeypatch.setattr(metrics, "_WORKER_FINALIZER", None)
    monkeypatch.setattr(metrics, "install_pass_wrappers", lambda _recorder: [])
    monkeypatch.setattr(
        metrics.multiprocessing.util,
        "Finalize",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setenv(metrics.WORKER_METRICS_ENV, str(second))

    metrics._ensure_worker_instrumentation()

    snapshot_path = first / f"{os.getpid()}.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    assert snapshot["build_cfg"]["invocation_count"] == 1
    assert snapshot["build_cfg"]["inclusive_wall_seconds"] == pytest.approx(0.25)
    assert metrics._WORKER_METRICS_DIR == str(second)
    assert metrics._WORKER_RECORDER is not recorder


def test_worker_item_uses_explicit_metrics_dir_and_flushes_on_failure(
    tmp_path, monkeypatch
):
    metrics = benchmark.pass_metrics
    monkeypatch.delenv(metrics.WORKER_METRICS_ENV, raising=False)
    monkeypatch.setattr(metrics, "_WORKER_RECORDER", None)
    monkeypatch.setattr(metrics, "_WORKER_PID", None)
    monkeypatch.setattr(metrics, "_WORKER_METRICS_DIR", None)
    monkeypatch.setattr(metrics, "_WORKER_RESTORATIONS", [])
    monkeypatch.setattr(metrics, "_WORKER_FINALIZER", None)
    monkeypatch.setattr(metrics, "install_pass_wrappers", lambda _recorder: [])
    monkeypatch.setattr(
        metrics.multiprocessing.util,
        "Finalize",
        lambda *args, **kwargs: object(),
    )

    def fail(item):
        assert all(
            name != metrics.WORKER_METRICS_OVERRIDE
            for name, _value in item.config_overrides
        )
        metrics._WORKER_RECORDER.add_pass("build_cfg", 0.5)
        raise RuntimeError("worker failed")

    monkeypatch.setattr(metrics, "_ORIGINAL_SCAN_WORKER_ITEM", fail)
    item = metrics.attach_worker_metrics_dir(
        parallel_workers.ParallelScanWorkItem(file_path="example.c"),
        tmp_path,
    )

    with pytest.raises(RuntimeError, match="worker failed"):
        metrics.benchmark_scan_worker_item(item)

    snapshot = json.loads(
        (tmp_path / f"{os.getpid()}.json").read_text(encoding="utf-8")
    )
    assert snapshot["build_cfg"]["invocation_count"] == 1
    assert snapshot["build_cfg"]["inclusive_wall_seconds"] == pytest.approx(0.5)


def test_snapshot_io_failure_never_changes_worker_result_or_exception(
    tmp_path, monkeypatch, capsys
):
    metrics = benchmark.pass_metrics
    monkeypatch.delenv(metrics.WORKER_METRICS_ENV, raising=False)
    monkeypatch.setattr(metrics, "_WORKER_RECORDER", None)
    monkeypatch.setattr(metrics, "_WORKER_PID", None)
    monkeypatch.setattr(metrics, "_WORKER_METRICS_DIR", None)
    monkeypatch.setattr(metrics, "_WORKER_RESTORATIONS", [])
    monkeypatch.setattr(metrics, "_WORKER_FINALIZER", None)
    monkeypatch.setattr(metrics, "install_pass_wrappers", lambda _recorder: [])
    monkeypatch.setattr(
        metrics.multiprocessing.util,
        "Finalize",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setattr(
        metrics.os,
        "replace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    item = metrics.attach_worker_metrics_dir(
        parallel_workers.ParallelScanWorkItem(file_path="example.c"),
        tmp_path,
    )

    sentinel = ("worker-result",)
    monkeypatch.setattr(metrics, "_ORIGINAL_SCAN_WORKER_ITEM", lambda _item: sentinel)
    assert metrics.benchmark_scan_worker_item(item) is sentinel

    def fail(_item):
        raise RuntimeError("original worker failure")

    monkeypatch.setattr(metrics, "_ORIGINAL_SCAN_WORKER_ITEM", fail)
    with pytest.raises(RuntimeError, match="original worker failure"):
        metrics.benchmark_scan_worker_item(item)

    assert "pass-metric snapshot write failed" in capsys.readouterr().err
    assert not list(tmp_path.glob("*.json"))


def test_parallel_sample_reports_complete_worker_snapshots(tmp_path):
    project = benchmark.generate_medium_project(
        tmp_path,
        modules=2,
        functions_per_module=1,
        statements_per_function=1,
    )

    sample = benchmark.run_sample(project, mode="tu", jobs=2, repetition=0)

    assert sample.pass_metric_expected_worker_snapshots > 0
    assert (
        sample.pass_metric_worker_snapshots
        == sample.pass_metric_expected_worker_snapshots
    )
    assert sample.pass_metric_worker_snapshots_complete is True
    assert sample.semantics.files_failed == 0
