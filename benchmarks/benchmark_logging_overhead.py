#!/usr/bin/env python3
"""Benchmark C-GULL logging overhead against the vendored Juliet corpus.

The benchmark compares three otherwise-identical end-to-end CLI scans:

* ``no_capture``: automatic JSONL capture disabled with ``--no-log``;
* ``default_capture``: default WARNING+ automatic JSONL capture;
* ``trace_capture``: automatic JSONL capture with ``-vvv`` (TRACE+).

It deliberately consumes scan telemetry emitted by the normal JSON reporter
instead of defining a benchmark-specific throughput metric.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET = REPO_ROOT / "benchmarks" / "juliet"
DEFAULT_REPETITIONS = 5
DEFAULT_WARMUPS = 1
DEFAULT_JOBS = 2
DEFAULT_THRESHOLD_PCT = 2.0
DEFAULT_SEED = 459


@dataclass(frozen=True)
class Arm:
    name: str
    cli_args: tuple[str, ...]
    description: str


ARMS = (
    Arm("no_capture", ("--no-log",), "automatic JSONL capture disabled"),
    Arm("default_capture", (), "default WARNING+ automatic JSONL capture"),
    Arm("trace_capture", ("-vvv",), "TRACE+ automatic JSONL capture"),
)
ARM_BY_NAME = {arm.name: arm for arm in ARMS}


@dataclass(frozen=True)
class Sample:
    arm: str
    repetition: int
    order_index: int
    throughput_kloc_per_sec: float
    analysis_elapsed_seconds: float
    wall_elapsed_seconds: float
    analyzed_lines: int
    capture_files: int
    capture_bytes: int


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure C-GULL default/TRACE logging overhead on Juliet",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=DEFAULT_TARGET,
        help="Juliet corpus directory to copy into an isolated benchmark workspace",
    )
    parser.add_argument(
        "--repetitions",
        type=_positive_int,
        default=DEFAULT_REPETITIONS,
        help=f"Measured repetitions per arm (default: {DEFAULT_REPETITIONS})",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=DEFAULT_WARMUPS,
        help=f"Warm-up cycles per arm, excluded from results (default: {DEFAULT_WARMUPS})",
    )
    parser.add_argument(
        "--jobs",
        type=_positive_int,
        default=DEFAULT_JOBS,
        help=f"Parallel worker count passed to C-GULL (default: {DEFAULT_JOBS})",
    )
    parser.add_argument(
        "--mode",
        choices=("file", "tu"),
        default="file",
        help="Explicit scan mode used identically by all arms (default: file)",
    )
    parser.add_argument(
        "--threshold-pct",
        type=float,
        default=DEFAULT_THRESHOLD_PCT,
        help="Release target for default-capture median throughput regression",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"Seed used to randomize per-cycle arm order (default: {DEFAULT_SEED})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for the complete JSON benchmark artifact",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter used to invoke 'python -m cgull'",
    )
    parser.add_argument(
        "--keep-workspace",
        action="store_true",
        help="Keep the isolated corpus/workspace after the benchmark for inspection",
    )
    args = parser.parse_args(argv)
    if args.warmup < 0:
        parser.error("--warmup must be zero or greater")
    if args.threshold_pct < 0:
        parser.error("--threshold-pct must be zero or greater")
    return args


def _revision(repo_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return completed.stdout.strip() or "unknown"


def _copy_corpus(source: Path, workspace: Path) -> Path:
    source = source.resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Juliet benchmark target is not a directory: {source}")
    corpus = workspace / "juliet"
    shutil.copytree(
        source,
        corpus,
        ignore=shutil.ignore_patterns(".cgull", "__pycache__", "*.pyc"),
    )
    return corpus


def _capture_paths(corpus: Path) -> list[Path]:
    return sorted((corpus / ".cgull" / "logs").glob("scan-*.log"))


def _clear_captures(corpus: Path) -> None:
    """Remove only benchmark-workspace automatic captures between repetitions."""
    for capture in _capture_paths(corpus):
        capture.unlink()
    log_dir = corpus / ".cgull" / "logs"
    if log_dir.is_dir():
        try:
            log_dir.rmdir()
            log_dir.parent.rmdir()
        except OSError:
            # Preserve unexpected non-capture artifacts rather than deleting them.
            pass


def _command(
    *,
    python: str,
    corpus: Path,
    report_path: Path,
    jobs: int,
    mode: str,
    arm: Arm,
) -> list[str]:
    return [
        python,
        "-m",
        "cgull",
        "scan",
        str(corpus),
        "--quiet",
        "--format",
        "json",
        "--output",
        str(report_path),
        "--jobs",
        str(jobs),
        "--mode",
        mode,
        *arm.cli_args,
    ]


def _load_telemetry(report_path: Path) -> dict[str, Any]:
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        telemetry = report["scan"]
        analyzed_lines = int(telemetry["analyzed_lines"])
        elapsed = float(telemetry["elapsed_seconds"])
        throughput = float(telemetry["throughput_kloc_per_sec"])
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid C-GULL JSON telemetry in {report_path}: {exc}") from exc
    if analyzed_lines <= 0 or elapsed <= 0.0 or throughput <= 0.0:
        raise RuntimeError(
            "benchmark requires positive analyzed_lines, elapsed_seconds, and "
            f"throughput_kloc_per_sec; got {telemetry!r}"
        )
    return telemetry


def _run_once(
    *,
    repo_root: Path,
    corpus: Path,
    reports_dir: Path,
    python: str,
    jobs: int,
    mode: str,
    arm: Arm,
    repetition: int,
    order_index: int,
    warmup: bool,
) -> Sample:
    _clear_captures(corpus)
    phase = "warmup" if warmup else "sample"
    report_path = reports_dir / f"{phase}-{repetition:02d}-{order_index}-{arm.name}.json"
    command = _command(
        python=python,
        corpus=corpus,
        report_path=report_path,
        jobs=jobs,
        mode=mode,
        arm=arm,
    )

    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wall_elapsed = time.perf_counter() - started
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic output"
        raise RuntimeError(
            f"{arm.name} scan exited with {completed.returncode}: {detail}"
        )

    telemetry = _load_telemetry(report_path)
    captures = _capture_paths(corpus)
    capture_bytes = sum(path.stat().st_size for path in captures)
    sample = Sample(
        arm=arm.name,
        repetition=repetition,
        order_index=order_index,
        throughput_kloc_per_sec=float(telemetry["throughput_kloc_per_sec"]),
        analysis_elapsed_seconds=float(telemetry["elapsed_seconds"]),
        wall_elapsed_seconds=wall_elapsed,
        analyzed_lines=int(telemetry["analyzed_lines"]),
        capture_files=len(captures),
        capture_bytes=capture_bytes,
    )
    _clear_captures(corpus)
    return sample


def _cycle_order(rng: random.Random) -> list[Arm]:
    order = list(ARMS)
    rng.shuffle(order)
    return order


def _validate_semantics(samples: Iterable[Sample]) -> int:
    materialized = list(samples)
    line_counts = {sample.analyzed_lines for sample in materialized}
    if len(line_counts) != 1:
        raise RuntimeError(
            "benchmark arms did not analyze identical volume: "
            f"analyzed_lines={sorted(line_counts)}"
        )
    analyzed_lines = next(iter(line_counts))
    if analyzed_lines <= 0:
        raise RuntimeError("benchmark produced no analyzed lines")

    for sample in materialized:
        if sample.arm == "no_capture" and sample.capture_files != 0:
            raise RuntimeError(
                "no_capture unexpectedly produced automatic capture files: "
                f"repetition={sample.repetition}, capture_files={sample.capture_files}"
            )
        if sample.arm in {"default_capture", "trace_capture"} and sample.capture_files <= 0:
            raise RuntimeError(
                f"{sample.arm} produced no automatic capture files: "
                f"repetition={sample.repetition}"
            )
    return analyzed_lines


def _median(values: Iterable[float]) -> float:
    materialized = list(values)
    if not materialized:
        raise ValueError("cannot compute a median without samples")
    return float(statistics.median(materialized))


def summarize(samples: Sequence[Sample], *, threshold_pct: float) -> dict[str, Any]:
    _validate_semantics(samples)
    by_arm: dict[str, dict[str, Any]] = {}
    for arm in ARMS:
        arm_samples = [sample for sample in samples if sample.arm == arm.name]
        if not arm_samples:
            raise ValueError(f"missing samples for {arm.name}")
        by_arm[arm.name] = {
            "description": arm.description,
            "median_throughput_kloc_per_sec": _median(
                sample.throughput_kloc_per_sec for sample in arm_samples
            ),
            "median_analysis_elapsed_seconds": _median(
                sample.analysis_elapsed_seconds for sample in arm_samples
            ),
            "median_wall_elapsed_seconds": _median(
                sample.wall_elapsed_seconds for sample in arm_samples
            ),
            "samples": [asdict(sample) for sample in arm_samples],
        }

    baseline = by_arm["no_capture"]["median_throughput_kloc_per_sec"]
    for arm_name in ("default_capture", "trace_capture"):
        measured = by_arm[arm_name]["median_throughput_kloc_per_sec"]
        by_arm[arm_name]["throughput_regression_pct_vs_no_capture"] = (
            (baseline - measured) / baseline * 100.0
        )
    by_arm["no_capture"]["throughput_regression_pct_vs_no_capture"] = 0.0

    default_regression = by_arm["default_capture"][
        "throughput_regression_pct_vs_no_capture"
    ]
    return {
        "arms": by_arm,
        "release_gate": {
            "metric": "median throughput_kloc_per_sec regression vs no_capture",
            "threshold_pct": threshold_pct,
            "default_capture_regression_pct": default_regression,
            "passes": default_regression < threshold_pct,
            "trace_is_informational": True,
        },
    }


def _print_summary(result: dict[str, Any]) -> None:
    print("C-GULL logging overhead benchmark")
    print("=" * 72)
    for arm in ARMS:
        entry = result["summary"]["arms"][arm.name]
        regression = entry["throughput_regression_pct_vs_no_capture"]
        print(
            f"{arm.name:16} "
            f"median={entry['median_throughput_kloc_per_sec']:.3f} KLOC/s  "
            f"analysis={entry['median_analysis_elapsed_seconds']:.3f}s  "
            f"wall={entry['median_wall_elapsed_seconds']:.3f}s  "
            f"regression={regression:+.2f}%"
        )
    gate = result["summary"]["release_gate"]
    print("-" * 72)
    status = "PASS" if gate["passes"] else "MISS"
    print(
        f"Default capture gate: {status} "
        f"({gate['default_capture_regression_pct']:.2f}% < {gate['threshold_pct']:.2f}%)"
    )
    print("TRACE is informational and is not subject to the default-capture gate.")


def run(args: argparse.Namespace) -> dict[str, Any]:
    repo_root = REPO_ROOT.resolve()
    target = args.target.resolve()
    rng = random.Random(args.seed)
    workspace_root = Path(tempfile.mkdtemp(prefix="cgull-logging-benchmark-"))
    try:
        corpus = _copy_corpus(target, workspace_root)
        reports_dir = workspace_root / "reports"
        reports_dir.mkdir()

        warmup_orders: list[list[str]] = []
        for cycle in range(args.warmup):
            order = _cycle_order(rng)
            warmup_orders.append([arm.name for arm in order])
            for order_index, arm in enumerate(order):
                _run_once(
                    repo_root=repo_root,
                    corpus=corpus,
                    reports_dir=reports_dir,
                    python=args.python,
                    jobs=args.jobs,
                    mode=args.mode,
                    arm=arm,
                    repetition=cycle,
                    order_index=order_index,
                    warmup=True,
                )

        samples: list[Sample] = []
        measured_orders: list[list[str]] = []
        for repetition in range(args.repetitions):
            order = _cycle_order(rng)
            measured_orders.append([arm.name for arm in order])
            for order_index, arm in enumerate(order):
                samples.append(
                    _run_once(
                        repo_root=repo_root,
                        corpus=corpus,
                        reports_dir=reports_dir,
                        python=args.python,
                        jobs=args.jobs,
                        mode=args.mode,
                        arm=arm,
                        repetition=repetition,
                        order_index=order_index,
                        warmup=False,
                    )
                )

        analyzed_lines = _validate_semantics(samples)
        result = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "environment": {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "python_executable": args.python,
                "cgull_revision": _revision(repo_root),
            },
            "configuration": {
                "source_target": str(target),
                "workspace_target": str(corpus),
                "jobs": args.jobs,
                "scan_mode": args.mode,
                "repetitions": args.repetitions,
                "warmup_cycles": args.warmup,
                "seed": args.seed,
                "analyzed_lines": analyzed_lines,
                "report_format": "json",
                "arm_order": measured_orders,
                "warmup_arm_order": warmup_orders,
            },
            "summary": summarize(samples, threshold_pct=args.threshold_pct),
        }

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result
    finally:
        if args.keep_workspace:
            print(f"Benchmark workspace retained at: {workspace_root}", file=sys.stderr)
        else:
            shutil.rmtree(workspace_root, ignore_errors=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = run(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    _print_summary(result)
    if args.output:
        print(f"JSON artifact: {args.output}")
    # A benchmark is an observation tool, not a flaky CI gate. The release-gate
    # verdict is recorded in the artifact and summary without changing exit code.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
