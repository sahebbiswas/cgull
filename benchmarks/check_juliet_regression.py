#!/usr/bin/env python3
"""Fail CI when CGULL-049 Juliet quality drops beyond its recorded budget."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Mapping, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = REPO_ROOT / "benchmarks" / "juliet" / "cgull-049-regression-baseline.json"
METRICS = ("precision", "recall", "f1")


def _load_json(path: Path) -> Mapping[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate_regression(
    report: Mapping[str, object],
    baseline: Mapping[str, object],
) -> Tuple[List[Dict[str, object]], List[str]]:
    """Return comparison rows and human-readable regression failures."""
    rule_id = str(baseline.get("rule_id", "CGULL-049"))
    default_budget = float(baseline.get("default_max_drop", 0.0))
    cwe_baselines = baseline.get("cwes", {})
    actual_by_cwe = report.get("by_cwe", {})

    if not isinstance(cwe_baselines, Mapping):
        raise ValueError("baseline.cwes must be an object")
    if not isinstance(actual_by_cwe, Mapping):
        raise ValueError("report.by_cwe must be an object")

    rows: List[Dict[str, object]] = []
    failures: List[str] = []

    failed_files = report.get("failed_files", [])
    if isinstance(failed_files, Sequence) and not isinstance(failed_files, (str, bytes)):
        max_failed_files = int(baseline.get("max_failed_files", 0))
        if len(failed_files) > max_failed_files:
            failures.append(
                f"{rule_id}: benchmark has {len(failed_files)} failed files; budget allows {max_failed_files}"
            )

    for cwe, expected_obj in cwe_baselines.items():
        if not isinstance(expected_obj, Mapping):
            raise ValueError(f"baseline for {cwe} must be an object")
        actual_obj = actual_by_cwe.get(cwe)
        if not isinstance(actual_obj, Mapping):
            failures.append(f"{rule_id}/{cwe}: metric row is missing from benchmark report")
            continue

        row: Dict[str, object] = {"rule_id": rule_id, "cwe": cwe}
        for metric in METRICS:
            baseline_value = float(expected_obj[metric])
            actual_value = float(actual_obj[metric])
            budget = float(expected_obj.get(f"max_{metric}_drop", default_budget))
            floor = max(0.0, baseline_value - budget)
            row[f"baseline_{metric}"] = baseline_value
            row[metric] = actual_value
            row[f"min_{metric}"] = floor
            if actual_value + 1e-12 < floor:
                failures.append(
                    f"{rule_id}/{cwe}: {metric} {actual_value:.4f} is below "
                    f"{floor:.4f} (baseline {baseline_value:.4f}, max drop {budget:.4f})"
                )
        rows.append(row)

    return rows, failures


def format_markdown(rows: Sequence[Mapping[str, object]], failures: Sequence[str]) -> str:
    lines = [
        "# CGULL-049 Juliet Regression Gate",
        "",
        "| Rule | CWE | Precision | Min | Recall | Min | F1 | Min |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['rule_id']} | {row['cwe']} | {float(row['precision']):.4f} | "
            f"{float(row['min_precision']):.4f} | {float(row['recall']):.4f} | "
            f"{float(row['min_recall']):.4f} | {float(row['f1']):.4f} | "
            f"{float(row['min_f1']):.4f} |"
        )
    lines.append("")
    if failures:
        lines.append("## Regressions")
        lines.extend(f"- {failure}" for failure in failures)
    else:
        lines.append("Result: PASS")
    return "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="JSON report produced by run_juliet_upstream.py")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--output", type=Path, help="Optional Markdown comparison report")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    rows, failures = evaluate_regression(_load_json(args.report), _load_json(args.baseline))
    rendered = format_markdown(rows, failures)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
