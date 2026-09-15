#!/usr/bin/env python3
"""Measure #490 structural CFG caching on the #486 medium-project workload.

The ``before`` lane disables the structural/session routing introduced by #490
while keeping the rest of the current analyzer unchanged. The ``after`` lane
uses the normal code path. Both lanes run the normal full-rule scanner with
``jobs=1`` so structural CFG construction can be counted in-process.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
import json
from pathlib import Path
import tempfile
from time import perf_counter

import benchmark_medium_project as medium
import cgull.analysis_session as analysis_session
import cgull.cfg.construction as construction


@dataclass
class CFGMetrics:
    count: int = 0
    seconds: float = 0.0


@contextmanager
def _measure_uncached_construction():
    metrics = CFGMetrics()
    original = construction.build_cfg_uncached

    def timed(*args, **kwargs):
        started = perf_counter()
        try:
            return original(*args, **kwargs)
        finally:
            metrics.count += 1
            metrics.seconds += perf_counter() - started

    construction.build_cfg_uncached = timed
    try:
        yield metrics
    finally:
        construction.build_cfg_uncached = original


@contextmanager
def _legacy_uncached_mode():
    """Approximate pre-#490 CFG behavior for an apples-to-apples comparison."""
    original_clone = construction.clone_cached_structural_cfg
    original_owner_lookup = analysis_session._analysis_session_for_funcdef

    def uncached_clone(funcdef, line_map=None):
        return construction.build_cfg_uncached(funcdef, line_map=line_map)

    construction.clone_cached_structural_cfg = uncached_clone
    analysis_session._analysis_session_for_funcdef = lambda _funcdef: None
    try:
        yield
    finally:
        construction.clone_cached_structural_cfg = original_clone
        analysis_session._analysis_session_for_funcdef = original_owner_lookup


def _run(project: Path, mode: str, *, legacy: bool):
    lane = _legacy_uncached_mode() if legacy else nullcontext()
    with lane:
        with _measure_uncached_construction() as metrics:
            sample = medium.run_sample(
                project,
                mode=mode,
                jobs=1,
                repetition=0,
            )
    return sample, metrics


def _sample_payload(sample, metrics: CFGMetrics) -> dict:
    return {
        "wall_seconds": sample.wall_seconds,
        "throughput_kloc_per_sec": sample.throughput_kloc_per_sec,
        "structural_cfg_construction_count": metrics.count,
        "structural_cfg_construction_seconds": metrics.seconds,
        "structural_cfg_fraction_of_wall": (
            metrics.seconds / sample.wall_seconds if sample.wall_seconds else 0.0
        ),
        "finding_count": sample.finding_count,
        "semantic_digest": sample.semantic_digest,
        "expanded_analysis_lines": sample.expanded_analysis_lines,
    }


def run_comparison(project: Path, modes: tuple[str, ...]) -> dict:
    comparisons = []
    all_parity = True
    for mode in modes:
        before_sample, before_metrics = _run(project, mode, legacy=True)
        after_sample, after_metrics = _run(project, mode, legacy=False)
        parity = before_sample.semantic_digest == after_sample.semantic_digest
        all_parity = all_parity and parity
        before = _sample_payload(before_sample, before_metrics)
        after = _sample_payload(after_sample, after_metrics)
        comparisons.append(
            {
                "mode": mode,
                "jobs": 1,
                "semantic_parity": parity,
                "before": before,
                "after": after,
                "delta": {
                    "wall_seconds": after["wall_seconds"] - before["wall_seconds"],
                    "structural_cfg_construction_count": (
                        after["structural_cfg_construction_count"]
                        - before["structural_cfg_construction_count"]
                    ),
                    "structural_cfg_construction_seconds": (
                        after["structural_cfg_construction_seconds"]
                        - before["structural_cfg_construction_seconds"]
                    ),
                },
                "ratio": {
                    "wall_time": (
                        after["wall_seconds"] / before["wall_seconds"]
                        if before["wall_seconds"]
                        else None
                    ),
                    "structural_cfg_construction_count": (
                        after["structural_cfg_construction_count"]
                        / before["structural_cfg_construction_count"]
                        if before["structural_cfg_construction_count"]
                        else None
                    ),
                    "structural_cfg_construction_time": (
                        after["structural_cfg_construction_seconds"]
                        / before["structural_cfg_construction_seconds"]
                        if before["structural_cfg_construction_seconds"]
                        else None
                    ),
                },
            }
        )
    return {
        "schema_version": 1,
        "benchmark": "issue-486-medium-project-cfg-cache",
        "workload": medium.workload_manifest(project),
        "semantic_parity": all_parity,
        "comparisons": comparisons,
    }


def _parse_modes(value: str) -> tuple[str, ...]:
    modes = tuple(part.strip() for part in value.split(",") if part.strip())
    invalid = set(modes) - {"file", "tu"}
    if invalid or not modes:
        raise argparse.ArgumentTypeError("modes must be a comma-separated subset of file,tu")
    return modes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modules", type=int, default=4)
    parser.add_argument("--functions-per-module", type=int, default=3)
    parser.add_argument("--statements-per-function", type=int, default=4)
    parser.add_argument("--modes", type=_parse_modes, default=("file", "tu"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="cgull-issue490-") as tmp:
        project = medium.generate_medium_project(
            Path(tmp),
            modules=args.modules,
            functions_per_module=args.functions_per_module,
            statements_per_function=args.statements_per_function,
        )
        report = run_comparison(project, args.modes)

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if report["semantic_parity"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
