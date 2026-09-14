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
COUNT_LIMITS = (
    ("tp", "min_tp", "minimum"),
    ("fp", "max_fp", "maximum"),
    ("fn", "max_fn", "maximum"),
)


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

    expected_schema = baseline.get("report_schema_version")
    if expected_schema is not None and report.get("schema_version") != expected_schema:
        failures.append(
            f"{rule_id}: report schema {report.get('schema_version')!r} does not match "
            f"baseline schema {expected_schema!r}"
        )

    failed_files = report.get("failed_files", [])
    if isinstance(failed_files, Sequence) and not isinstance(failed_files, (str, bytes)):
        max_failed_files = int(baseline.get("max_failed_files", 0))
        if len(failed_files) > max_failed_files:
            failures.append(
                f"{rule_id}: benchmark has {len(failed_files)} failed files; budget allows {max_failed_files}"
            )
    else:
        failures.append(f"{rule_id}: benchmark report has invalid failed_files metadata")

    for cwe, expected_obj in cwe_baselines.items():
        if not isinstance(expected_obj, Mapping):
            raise ValueError(f"baseline for {cwe} must be an object")
        actual_obj = actual_by_cwe.get(cwe)
        if not isinstance(actual_obj, Mapping):
            failures.append(f"{rule_id}/{cwe}: metric row is missing from benchmark report")
            continue

        row: Dict[str, object] = {"rule_id": rule_id, "cwe": cwe}
        for count in ("tp", "fp", "tn", "fn"):
            value = actual_obj.get(count)
            row[count] = int(value) if value is not None else None

        for count, limit_key, direction in COUNT_LIMITS:
            if limit_key not in expected_obj:
                continue
            value = actual_obj.get(count)
            if value is None:
                failures.append(f"{rule_id}/{cwe}: {count} is missing from benchmark report")
                continue
            actual_count = int(value)
            limit = int(expected_obj[limit_key])
            violates = actual_count < limit if direction == "minimum" else actual_count > limit
            if violates:
                comparator = "below" if direction == "minimum" else "above"
                failures.append(
                    f"{rule_id}/{cwe}: {count} {actual_count} is {comparator} "
                    f"the {direction} budget {limit}"
                )

        for metric in METRICS:
            if metric not in expected_obj:
                raise ValueError(f"baseline for {cwe} is missing required metric {metric}")
            baseline_value = float(expected_obj[metric])
            budget = float(expected_obj.get(f"max_{metric}_drop", default_budget))
            floor = max(0.0, baseline_value - budget)
            row[f"baseline_{metric}"] = baseline_value
            row[f"min_{metric}"] = floor

            if metric not in actual_obj:
                row[metric] = None
                failures.append(f"{rule_id}/{cwe}: {metric} is missing from benchmark report")
                continue

            actual_value = float(actual_obj[metric])
            row[metric] = actual_value
            if actual_value + 1e-12 < floor:
                failures.append(
                    f"{rule_id}/{cwe}: {metric} {actual_value:.4f} is below "
                    f"{floor:.4f} (baseline {baseline_value:.4f}, max drop {budget:.4f})"
                )
        rows.append(row)

    return rows, failures


def _fmt_float(value: object) -> str:
    return "missing" if value is None else f"{float(value):.4f}"


def _fmt_int(value: object) -> str:
    return "missing" if value is None else str(int(value))


def format_markdown(rows: Sequence[Mapping[str, object]], failures: Sequence[str]) -> str:
    lines = [
        "# CGULL-049 Juliet Regression Gate",
        "",
        "| Rule | CWE | TP | FP | FN | Precision | Min | Recall | Min | F1 | Min |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['rule_id']} | {row['cwe']} | {_fmt_int(row.get('tp'))} | "
            f"{_fmt_int(row.get('fp'))} | {_fmt_int(row.get('fn'))} | "
            f"{_fmt_float(row.get('precision'))} | {_fmt_float(row.get('min_precision'))} | "
            f"{_fmt_float(row.get('recall'))} | {_fmt_float(row.get('min_recall'))} | "
            f"{_fmt_float(row.get('f1'))} | {_fmt_float(row.get('min_f1'))} |"
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
