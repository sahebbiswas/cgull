#!/usr/bin/env python3
"""Compare full and restricted-rule project-summary cost on the #486 workload.

The helper intentionally uses only public scan configuration plus the existing
medium-project instrumentation, so the same file can be copied into a baseline
checkout from before #489 and run unchanged for a before/after comparison.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time


REPO_ROOT = Path.cwd().resolve()
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "benchmarks"))

import benchmark_medium_project as medium  # noqa: E402
from cgull import ScanConfig, ScanMode  # noqa: E402
from cgull.project_analysis import DOMAINS  # noqa: E402
from cgull.rules import FormatStringRule  # noqa: E402


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Benchmark demand-driven project-summary construction",
    )
    parser.add_argument("--modules", type=_positive_int, default=medium.DEFAULT_MODULES)
    parser.add_argument(
        "--functions-per-module",
        type=_positive_int,
        default=medium.DEFAULT_FUNCTIONS_PER_MODULE,
    )
    parser.add_argument(
        "--statements-per-function",
        type=_positive_int,
        default=medium.DEFAULT_STATEMENTS_PER_FUNCTION,
    )
    parser.add_argument("--repetitions", type=_positive_int, default=3)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--label", default="working-tree")
    return parser.parse_args(argv)


def _requirements(config):
    """Describe requirements when #489 exists; remain runnable on older bases."""
    try:
        from cgull.analysis_requirements import (
            project_summary_domains,
            required_analysis_for_rules,
        )
    except ImportError:
        return {
            "analysis_requirements": "legacy-all",
            "project_summary_domains": list(DOMAINS),
        }

    requirements = required_analysis_for_rules(config.get_rules())
    return {
        "analysis_requirements": list(requirements),
        "project_summary_domains": list(project_summary_domains(requirements)),
    }


def _capture(project, *, rules, repetition):
    recorder = medium.PhaseRecorder()
    config = ScanConfig.create(
        rules=rules,
        mode=ScanMode.FILE,
        include_roots=[str(project / "include")],
    )
    scanner = medium.BenchmarkScanner(recorder, config=config)
    with medium.phase_instrumentation(recorder):
        started = time.perf_counter()
        result = scanner.scan_path(str(project), jobs=1, quiet=True)
        wall_seconds = max(1e-9, time.perf_counter() - started)

    snapshot = medium._semantic_snapshot(result)
    return {
        "repetition": repetition,
        "wall_seconds": wall_seconds,
        "project_preparation_seconds": recorder.value("project_preparation_seconds"),
        "project_indexing_seconds": recorder.value("project_indexing_seconds"),
        "project_summary_construction_seconds": recorder.value(
            "project_summary_construction_seconds"
        ),
        "finding_count": result.total_issues_count,
        "semantic_digest": medium._semantic_digest(snapshot),
        "rules": [rule.rule_id for rule in config.get_rules()],
        **_requirements(config),
    }


def _arm(project, *, name, rule_factory, repetitions):
    samples = [
        _capture(
            project,
            rules=None if rule_factory is None else rule_factory(),
            repetition=repetition,
        )
        for repetition in range(repetitions)
    ]
    digests = {sample["semantic_digest"] for sample in samples}
    if len(digests) != 1:
        raise RuntimeError(f"semantic instability across {name} repetitions")
    return {
        "name": name,
        "rules": "default" if rule_factory is None else samples[0]["rules"],
        "analysis_requirements": samples[0]["analysis_requirements"],
        "project_summary_domains": samples[0]["project_summary_domains"],
        "finding_count": samples[0]["finding_count"],
        "median_wall_seconds": statistics.median(
            sample["wall_seconds"] for sample in samples
        ),
        "median_project_preparation_seconds": statistics.median(
            sample["project_preparation_seconds"] for sample in samples
        ),
        "median_project_indexing_seconds": statistics.median(
            sample["project_indexing_seconds"] for sample in samples
        ),
        "median_project_summary_construction_seconds": statistics.median(
            sample["project_summary_construction_seconds"] for sample in samples
        ),
        "samples": samples,
    }


def build_artifact(project, *, args):
    arms = {
        "default": _arm(
            project,
            name="default",
            rule_factory=None,
            repetitions=args.repetitions,
        ),
        "format-string-only": _arm(
            project,
            name="format-string-only",
            rule_factory=lambda: [FormatStringRule()],
            repetitions=args.repetitions,
        ),
    }
    return {
        "schema_version": 1,
        "label": args.label,
        "revision": medium._revision(),
        "workload": {
            **medium.workload_manifest(project),
            "modules": args.modules,
            "functions_per_module": args.functions_per_module,
            "statements_per_function": args.statements_per_function,
        },
        "repetitions": args.repetitions,
        "arms": arms,
    }


def _print_summary(artifact):
    print(f"C-GULL project-summary requirement benchmark ({artifact['label']})")
    for name, arm in artifact["arms"].items():
        domains = arm["project_summary_domains"]
        domains_text = ",".join(domains) if isinstance(domains, list) else str(domains)
        print(
            f"{name:20s} summary={arm['median_project_summary_construction_seconds']:.6f}s "
            f"wall={arm['median_wall_seconds']:.6f}s domains={domains_text}"
        )


def main(argv=None):
    args = parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="cgull-summary-requirements-") as workspace:
        project = medium.generate_medium_project(
            Path(workspace),
            modules=args.modules,
            functions_per_module=args.functions_per_module,
            statements_per_function=args.statements_per_function,
        )
        artifact = build_artifact(project, args=args)
        _print_summary(artifact)
        payload = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload, encoding="utf-8")
            print(f"JSON artifact: {args.output}")
        elif not sys.stdout.isatty():
            print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
