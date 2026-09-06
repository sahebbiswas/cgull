#!/usr/bin/env python3
"""Run release gates for C-GULL's intra-TU interprocedural analysis."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List, Sequence, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmarks.run_interprocedural import DEFAULT_MANIFEST, run_interprocedural_corpus
from cgull.cfg.fixed_point import FixedPointConfig
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine, ConfigProfile, ScanConfig, ScanMode
from cgull.rules import get_rule_by_id


DEFAULT_BUDGETS = os.path.join(
    REPO_ROOT, "benchmarks", "interprocedural", "release_budgets.json"
)
FIXTURE_ROOT = os.path.join(REPO_ROOT, "benchmarks", "interprocedural", "fixtures")
ACCEPTANCE_RULES = ("CGULL-001", "CGULL-002", "CGULL-022", "CGULL-044")


def _normalize_findings(result, root: str) -> Tuple[Tuple[Any, ...], ...]:
    normalized = []
    for issue in result.issues:
        path = os.path.relpath(os.path.abspath(issue.file_path), root).replace(os.sep, "/")
        normalized.append(
            (
                path,
                issue.rule_id,
                issue.line_number,
                issue.column_number,
                issue.message,
                issue.code_snippet.strip(),
            )
        )
    return tuple(sorted(normalized))


def _scan(
    target: Sequence[str] | str,
    *,
    mode: ScanMode,
    jobs: int,
    profiles: List[ConfigProfile] | None = None,
):
    rules = [get_rule_by_id(rule_id) for rule_id in ACCEPTANCE_RULES]
    config = ScanConfig.create(
        rules=rules,
        engine_mode=AnalysisEngine.HYBRID,
        mode=mode,
    )
    scanner = CGullScanner(config=config)
    started = time.perf_counter()
    result = scanner.scan_path(target, jobs=jobs, quiet=True, profiles=profiles)
    elapsed = time.perf_counter() - started
    return result, elapsed


def _measure_scan(
    target: Sequence[str] | str,
    *,
    mode: ScanMode,
    profiles: List[ConfigProfile] | None = None,
) -> Dict[str, Any]:
    tracemalloc.start()
    try:
        result, elapsed = _scan(target, mode=mode, jobs=1, profiles=profiles)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return {
        "wall_seconds": elapsed,
        "peak_memory_bytes": peak,
        "findings": len(result.issues),
        "files_analyzed": result.files_analyzed,
        "scan_failed": bool(
            result.failed_paths
            or result.files_failed
            or result.get_overall_analysis_status() == "failed"
        ),
    }


def _stress_sources(directory: str) -> Dict[str, str]:
    macro_lines = ["#define FEATURE_%d %d" % (index, index % 2) for index in range(96)]
    macro_lines.extend(
        "#if FEATURE_%d\nint feature_%d(void) { return %d; }\n#endif" % (index, index, index)
        for index in range(96)
    )
    macro_lines.append('void macro_sink(char *fmt) { printf(fmt); }')

    deep = ["char *source(void) { return \"%s\"; }"]
    for index in range(64):
        previous = "source" if index == 0 else "wrap_%d" % (index - 1)
        deep.append("char *wrap_%d(void) { return %s(); }" % (index, previous))
    deep.append("void deep_sink(void) { printf(wrap_63()); }")

    recursive = []
    count = 32
    for index in range(count):
        next_index = (index + 1) % count
        recursive.append(
            "char *rec_%d(int n) { if (n <= 0) return \"%%s\"; return rec_%d(n - 1); }"
            % (index, next_index)
        )
    recursive.append("void recursive_sink(void) { printf(rec_0(4)); }")

    sources = {
        "macro_heavy.c": "\n".join(macro_lines) + "\n",
        "deep_wrappers.c": "\n".join(deep) + "\n",
        "recursive_scc.c": "\n".join(recursive) + "\n",
    }
    paths: Dict[str, str] = {}
    for name, source in sources.items():
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)
        paths[name] = path
    return paths


def _precision_recall(metrics: Dict[str, int]) -> Dict[str, float]:
    tp = metrics["tp"]
    fp = metrics["fp"]
    fn = metrics["fn"]
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {"precision": precision, "recall": recall}


def _regression_deltas(regression: Dict[str, Any]) -> Dict[str, Any]:
    recorded = regression["recorded_baseline"]["by_rule"]
    current = regression["current"]["by_rule"]
    deltas: Dict[str, Any] = {}
    for rule_id in sorted(set(recorded) | set(current)):
        before = _precision_recall(recorded.get(rule_id, {"tp": 0, "fp": 0, "fn": 0}))
        after = _precision_recall(current.get(rule_id, {"tp": 0, "fp": 0, "fn": 0}))
        deltas[rule_id] = {
            "precision": after["precision"],
            "recall": after["recall"],
            "precision_delta": after["precision"] - before["precision"],
            "recall_delta": after["recall"] - before["recall"],
        }
    return deltas


def _acceptance_rule_checks() -> Dict[str, Any]:
    cases = {
        "CGULL-001": [
            (os.path.join(FIXTURE_ROOT, "data_dependent_scanf_unsafe.c"), True),
            (os.path.join(FIXTURE_ROOT, "data_dependent_scanf_safe.c"), False),
        ]
    }
    details = []
    failures = []
    for rule_id, rule_cases in cases.items():
        scanner = CGullScanner(rules=[get_rule_by_id(rule_id)], engine_mode=AnalysisEngine.HYBRID)
        for path, expected in rule_cases:
            result = scanner.scan_path(path, quiet=True)
            detected = any(issue.rule_id == rule_id for issue in result.issues)
            details.append(
                {
                    "rule_id": rule_id,
                    "file": os.path.basename(path),
                    "expected": expected,
                    "detected": detected,
                }
            )
            if detected != expected:
                failures.append(
                    "%s:%s expected detected=%s got %s"
                    % (rule_id, os.path.basename(path), expected, detected)
                )
    return {"success": not failures, "failures": failures, "cases": details}


def _determinism_matrix(targets: Sequence[str]) -> Dict[str, Any]:
    profile = [ConfigProfile(name="release-gate", flags={"CGULL_RELEASE_GATE": 1})]
    matrix = [
        ("file-sequential", "file", ScanMode.FILE, 1, None),
        ("file-repeat", "file", ScanMode.FILE, 1, None),
        ("file-parallel", "file", ScanMode.FILE, 2, None),
        ("tu-sequential", "tu", ScanMode.TU, 1, None),
        ("tu-repeat", "tu", ScanMode.TU, 1, None),
        ("tu-parallel", "tu", ScanMode.TU, 2, None),
        ("profile-sequential", "profile", ScanMode.FILE, 1, profile),
        ("profile-repeat", "profile", ScanMode.FILE, 1, profile),
        ("profile-parallel", "profile", ScanMode.FILE, 2, profile),
    ]
    runs = []
    baselines: Dict[str, Tuple[Tuple[Any, ...], ...]] = {}
    failures = []
    for label, group, mode, jobs, profiles in matrix:
        result, elapsed = _scan(targets, mode=mode, jobs=jobs, profiles=profiles)
        normalized = _normalize_findings(result, FIXTURE_ROOT)
        baseline = baselines.setdefault(group, normalized)
        matches = normalized == baseline
        scan_failed = bool(
            result.failed_paths
            or result.files_failed
            or result.get_overall_analysis_status() == "failed"
        )
        if not matches or scan_failed:
            failures.append(label)
        runs.append(
            {
                "name": label,
                "group": group,
                "mode": mode.value,
                "jobs": jobs,
                "wall_seconds": elapsed,
                "finding_count": len(normalized),
                "matches_group_baseline": matches,
                "scan_failed": scan_failed,
            }
        )
    return {"success": not failures, "mismatched_runs": failures, "runs": runs}


def _evaluate_budgets(performance: Dict[str, Any], budgets: Dict[str, Any]) -> List[str]:
    failures = []
    limits = budgets["performance"]
    for name, result in performance.items():
        if result["scan_failed"]:
            failures.append("%s scan failed" % name)
        if result["wall_seconds"] > limits["max_wall_seconds"]:
            failures.append(
                "%s wall time %.3fs exceeds %.3fs"
                % (name, result["wall_seconds"], limits["max_wall_seconds"])
            )
        if result["peak_memory_bytes"] > limits["max_peak_memory_bytes"]:
            failures.append(
                "%s peak memory %d exceeds %d"
                % (name, result["peak_memory_bytes"], limits["max_peak_memory_bytes"])
            )

    baseline = performance.get("representative_corpus")
    profiled = performance.get("representative_profile")
    if baseline and profiled:
        runtime_floor = limits.get("profile_runtime_ratio_min_baseline_seconds", 0.5)
        memory_floor = limits.get("profile_memory_ratio_min_baseline_bytes", 16 * 1024 * 1024)
        if baseline["wall_seconds"] >= runtime_floor:
            runtime_ratio = profiled["wall_seconds"] / baseline["wall_seconds"]
            if runtime_ratio > limits["max_profile_runtime_overhead_ratio"]:
                failures.append(
                    "profile runtime overhead %.3fx exceeds %.3fx"
                    % (runtime_ratio, limits["max_profile_runtime_overhead_ratio"])
                )
        if baseline["peak_memory_bytes"] >= memory_floor:
            memory_ratio = profiled["peak_memory_bytes"] / baseline["peak_memory_bytes"]
            if memory_ratio > limits["max_profile_memory_overhead_ratio"]:
                failures.append(
                    "profile memory overhead %.3fx exceeds %.3fx"
                    % (memory_ratio, limits["max_profile_memory_overhead_ratio"])
                )
    return failures


def run_release_gate(
    manifest_path: str = DEFAULT_MANIFEST,
    budgets_path: str = DEFAULT_BUDGETS,
) -> Dict[str, Any]:
    with open(budgets_path, "r", encoding="utf-8") as handle:
        budgets = json.load(handle)

    regression = run_interprocedural_corpus(manifest_path)
    acceptance = _acceptance_rule_checks()
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    manifest_dir = os.path.dirname(os.path.abspath(manifest_path))
    targets = sorted(
        {
            os.path.join(manifest_dir, case["file"])
            for case in manifest["cases"]
            if case["rule_id"] in ACCEPTANCE_RULES
        }
        | {
            os.path.join(FIXTURE_ROOT, "data_dependent_scanf_unsafe.c"),
            os.path.join(FIXTURE_ROOT, "data_dependent_scanf_safe.c"),
        }
    )

    determinism = _determinism_matrix(targets)
    profile = [ConfigProfile(name="release-gate", flags={"CGULL_RELEASE_GATE": 1})]
    performance: Dict[str, Any] = {
        "representative_corpus": _measure_scan(targets, mode=ScanMode.FILE),
        "representative_profile": _measure_scan(
            targets,
            mode=ScanMode.FILE,
            profiles=profile,
        ),
    }
    with tempfile.TemporaryDirectory(prefix="cgull-release-gate-") as temp_dir:
        for name, path in _stress_sources(temp_dir).items():
            performance[name] = _measure_scan(path, mode=ScanMode.FILE)

    failures: List[str] = []
    if not regression["success"]:
        failures.extend("regression: " + item for item in regression["failures"])
    if not acceptance["success"]:
        failures.extend("acceptance: " + item for item in acceptance["failures"])
    if not determinism["success"]:
        failures.append(
            "determinism mismatch: " + ", ".join(determinism["mismatched_runs"])
        )
    failures.extend(_evaluate_budgets(performance, budgets))

    fixed_point = FixedPointConfig()
    if fixed_point.max_iterations_per_scc > budgets["analysis_limits"]["max_summary_iterations"]:
        failures.append("configured summary iteration limit exceeds release budget")
    if fixed_point.max_provenance > budgets["analysis_limits"]["max_provenance"]:
        failures.append("configured provenance limit exceeds release budget")

    return {
        "suite": "C-GULL Interprocedural Release Gate",
        "version": "1.0",
        "success": not failures,
        "failures": failures,
        "budgets": budgets,
        "analysis_limits": {
            "max_summary_iterations": fixed_point.max_iterations_per_scc,
            "max_provenance": fixed_point.max_provenance,
        },
        "regression": {
            "success": regression["success"],
            "current": regression["current"],
            "precision_recall_by_rule": _regression_deltas(regression),
        },
        "acceptance_rules": acceptance,
        "determinism": determinism,
        "performance": performance,
    }


def format_text_report(results: Dict[str, Any]) -> str:
    lines = [results["suite"], "=" * len(results["suite"])]
    lines.append("status: %s" % ("PASS" if results["success"] else "FAIL"))
    lines.append("determinism: %s" % ("PASS" if results["determinism"]["success"] else "FAIL"))
    lines.append("acceptance rules: %s" % ("PASS" if results["acceptance_rules"]["success"] else "FAIL"))
    lines.append("performance:")
    for name, metrics in sorted(results["performance"].items()):
        lines.append(
            "- %s: %.3fs, %.1f MiB peak"
            % (name, metrics["wall_seconds"], metrics["peak_memory_bytes"] / (1024 * 1024))
        )
    lines.append("precision/recall:")
    for rule_id, metrics in sorted(results["regression"]["precision_recall_by_rule"].items()):
        lines.append(
            "- %s: precision %.3f (%+.3f), recall %.3f (%+.3f)"
            % (
                rule_id,
                metrics["precision"],
                metrics["precision_delta"],
                metrics["recall"],
                metrics["recall_delta"],
            )
        )
    if results["failures"]:
        lines.append("failures:")
        lines.extend("- " + failure for failure in results["failures"])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--budgets", default=DEFAULT_BUDGETS)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output")
    parser.add_argument("--ci", action="store_true", help="exit nonzero when a release gate fails")
    args = parser.parse_args()

    results = run_release_gate(args.manifest, args.budgets)
    report = (
        json.dumps(results, indent=2, sort_keys=True)
        if args.format == "json"
        else format_text_report(results)
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(report)
            handle.write("\n")
    else:
        print(report)
    if args.ci and not results["success"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
