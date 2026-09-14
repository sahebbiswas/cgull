from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


MODULE_PATH = Path(__file__).parents[1] / "benchmarks" / "benchmark_logging_overhead.py"
SPEC = importlib.util.spec_from_file_location("benchmark_logging_overhead", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


def sample(
    arm: str,
    repetition: int,
    throughput: float,
    analysis: float,
    wall: float,
    *,
    analyzed_lines: int = 10000,
):
    return benchmark.Sample(
        arm=arm,
        repetition=repetition,
        order_index=0,
        throughput_kloc_per_sec=throughput,
        analysis_elapsed_seconds=analysis,
        wall_elapsed_seconds=wall,
        analyzed_lines=analyzed_lines,
        capture_files=0 if arm == "no_capture" else 1,
        capture_bytes=0 if arm == "no_capture" else 123,
    )


def test_summary_uses_medians_and_default_release_gate():
    samples = [
        sample("no_capture", 0, 100.0, 1.00, 1.10),
        sample("no_capture", 1, 102.0, 0.98, 1.08),
        sample("no_capture", 2, 98.0, 1.02, 1.12),
        sample("default_capture", 0, 99.0, 1.01, 1.11),
        sample("default_capture", 1, 101.0, 0.99, 1.09),
        sample("default_capture", 2, 98.5, 1.02, 1.12),
        sample("trace_capture", 0, 90.0, 1.10, 1.20),
        sample("trace_capture", 1, 89.0, 1.12, 1.22),
        sample("trace_capture", 2, 91.0, 1.08, 1.18),
    ]

    result = benchmark.summarize(samples, threshold_pct=2.0)

    assert result["arms"]["no_capture"]["median_throughput_kloc_per_sec"] == 100.0
    assert result["arms"]["default_capture"]["median_throughput_kloc_per_sec"] == 99.0
    assert result["arms"]["default_capture"]["throughput_regression_pct_vs_no_capture"] == pytest.approx(1.0)
    assert result["arms"]["trace_capture"]["throughput_regression_pct_vs_no_capture"] == pytest.approx(10.0)
    assert result["release_gate"]["passes"] is True
    assert result["release_gate"]["trace_is_informational"] is True


def test_release_gate_is_strictly_less_than_two_percent():
    samples = []
    for repetition in range(5):
        samples.extend(
            [
                sample("no_capture", repetition, 100.0, 1.0, 1.0),
                sample("default_capture", repetition, 98.0, 1.0, 1.0),
                sample("trace_capture", repetition, 80.0, 1.0, 1.0),
            ]
        )

    result = benchmark.summarize(samples, threshold_pct=2.0)

    assert result["release_gate"]["default_capture_regression_pct"] == pytest.approx(2.0)
    assert result["release_gate"]["passes"] is False


def test_summary_rejects_different_analysis_volume_between_arms():
    samples = [
        sample("no_capture", 0, 100.0, 1.0, 1.0, analyzed_lines=10000),
        sample("default_capture", 0, 99.0, 1.0, 1.0, analyzed_lines=9999),
        sample("trace_capture", 0, 90.0, 1.0, 1.0, analyzed_lines=10000),
    ]

    with pytest.raises(RuntimeError, match="identical volume"):
        benchmark.summarize(samples, threshold_pct=2.0)


def test_command_keeps_scan_semantics_equal_and_only_arm_flags_change(tmp_path):
    corpus = tmp_path / "juliet"
    report = tmp_path / "report.json"
    common = {
        "python": "python-test",
        "corpus": corpus,
        "report_path": report,
        "jobs": 4,
        "mode": "tu",
    }

    no_capture = benchmark._command(arm=benchmark.ARM_BY_NAME["no_capture"], **common)
    default_capture = benchmark._command(arm=benchmark.ARM_BY_NAME["default_capture"], **common)
    trace_capture = benchmark._command(arm=benchmark.ARM_BY_NAME["trace_capture"], **common)

    assert no_capture[:-1] == default_capture
    assert no_capture[-1] == "--no-log"
    assert trace_capture[:-1] == default_capture
    assert trace_capture[-1] == "-vvv"
    assert default_capture[:4] == ["python-test", "-m", "cgull", "scan"]
    jobs_index = default_capture.index("--jobs")
    mode_index = default_capture.index("--mode")
    assert default_capture[jobs_index:jobs_index + 2] == ["--jobs", "4"]
    assert default_capture[mode_index:mode_index + 2] == ["--mode", "tu"]


def test_cycle_order_is_reproducible_but_not_fixed():
    first_rng = benchmark.random.Random(459)
    second_rng = benchmark.random.Random(459)

    first = [[arm.name for arm in benchmark._cycle_order(first_rng)] for _ in range(4)]
    second = [[arm.name for arm in benchmark._cycle_order(second_rng)] for _ in range(4)]

    assert first == second
    assert any(order != [arm.name for arm in benchmark.ARMS] for order in first)
    assert all(sorted(order) == sorted(benchmark.ARM_BY_NAME) for order in first)


def test_clear_captures_only_deletes_owned_capture_files(tmp_path):
    corpus = tmp_path / "juliet"
    log_dir = corpus / ".cgull" / "logs"
    log_dir.mkdir(parents=True)
    capture = log_dir / "scan-20260914T120000.000000Z-123.log"
    unrelated = log_dir / "notes.txt"
    capture.write_text("{}\n", encoding="utf-8")
    unrelated.write_text("keep", encoding="utf-8")

    benchmark._clear_captures(corpus)

    assert not capture.exists()
    assert unrelated.read_text(encoding="utf-8") == "keep"


def test_parse_args_requires_parallel_jobs_to_be_positive():
    with pytest.raises(SystemExit):
        benchmark.parse_args(["--jobs", "0"])
