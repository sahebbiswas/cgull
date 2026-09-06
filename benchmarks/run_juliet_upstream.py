#!/usr/bin/env python3
"""Run C-GULL against the upstream Juliet 1.3 suite.

The upstream checkout remains the canonical source. This runner discovers cases
using Juliet's function-name convention instead of a hand-authored per-file
manifest. It supports both a deterministic stratified PR sample and a full run
across every discoverable entry file for C-GULL's mapped CWEs.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmarks.run_juliet import CWE_RULE_MAP, compute_metrics, extract_function_line_ranges
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine

DEFAULT_FLOW_VARIANTS = ("01", "02", "04", "08", "31", "54", "61")
FLOW_RE = re.compile(r"_(\d{2})(?:[a-z])?\.(?:c|cpp)$", re.IGNORECASE)


def normalize_cwe(value: str) -> str:
    value = value.upper().replace("_", "-")
    if value.startswith("CWE") and not value.startswith("CWE-"):
        value = f"CWE-{value[3:]}"
    return value


def _cwe_directory(root: Path, cwe: str) -> Path | None:
    number = cwe.split("-", 1)[1]
    candidates = sorted((root / "testcases").glob(f"CWE{number}_*"))
    return candidates[0] if candidates else None


def infer_oracles(path: Path) -> List[Tuple[str, bool]]:
    """Return (function, vulnerable) pairs using Juliet's bad/good convention."""
    ranges = extract_function_line_ranges(str(path))
    oracles: List[Tuple[str, bool]] = []
    for name in sorted(ranges):
        lower = name.lower()
        if lower == "bad" or lower.endswith("_bad"):
            oracles.append((name, True))
        elif lower == "good" or lower.startswith("good") or "_good" in lower:
            oracles.append((name, False))
    return oracles


def flow_variant(path: Path) -> str | None:
    match = FLOW_RE.search(path.name)
    return match.group(1) if match else None


def discover_candidates(suite_root: Path, cwe: str) -> List[Path]:
    directory = _cwe_directory(suite_root, cwe)
    if directory is None:
        return []
    candidates: List[Path] = []
    for path in sorted(directory.rglob("*")):
        if path.suffix.lower() not in {".c", ".cpp"}:
            continue
        if infer_oracles(path):
            candidates.append(path)
    return candidates


def select_all_cases(suite_root: Path, cwes: Sequence[str]) -> List[Tuple[str, Path]]:
    return [
        (cwe, path)
        for cwe in cwes
        for path in discover_candidates(suite_root, cwe)
    ]


def select_stratified_cases(
    suite_root: Path,
    cwes: Sequence[str],
    flow_variants: Sequence[str],
    per_flow: int,
) -> List[Tuple[str, Path]]:
    selected: List[Tuple[str, Path]] = []
    for cwe in cwes:
        by_flow: Dict[str, List[Path]] = defaultdict(list)
        for path in discover_candidates(suite_root, cwe):
            variant = flow_variant(path)
            if variant in flow_variants:
                by_flow[variant].append(path)
        for variant in flow_variants:
            for path in by_flow.get(variant, [])[:per_flow]:
                selected.append((cwe, path))
    return selected


def _issue_in_range(issue, start: int, end: int) -> bool:
    return start <= issue.line_number <= end


def run_benchmark(cases: Sequence[Tuple[str, Path]]) -> Dict[str, object]:
    scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)
    stats: Dict[str, Dict[str, int]] = {
        cwe: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for cwe in CWE_RULE_MAP
    }
    evaluated = 0
    failed_files: List[str] = []

    for cwe, path in cases:
        ranges = extract_function_line_ranges(str(path))
        result = scanner.scan_path(str(path))
        if result.files_failed or result.failed_paths or result.get_overall_analysis_status() == "failed":
            failed_files.append(str(path))
            continue
        relevant_rules = CWE_RULE_MAP[cwe]
        for function, vulnerable in infer_oracles(path):
            start, end = ranges[function]
            detected = any(
                issue.rule_id in relevant_rules and _issue_in_range(issue, start, end)
                for issue in result.issues
            )
            evaluated += 1
            if vulnerable and detected:
                stats[cwe]["tp"] += 1
            elif vulnerable:
                stats[cwe]["fn"] += 1
            elif detected:
                stats[cwe]["fp"] += 1
            else:
                stats[cwe]["tn"] += 1

    by_cwe = {
        cwe: compute_metrics(**counts)
        for cwe, counts in stats.items()
        if sum(counts.values())
    }
    overall_counts = {
        key: sum(item[key] for item in stats.values())
        for key in ("tp", "fp", "tn", "fn")
    }
    return {
        "schema_version": 1,
        "selected_files": len(cases),
        "evaluated_functions": evaluated,
        "failed_files": failed_files,
        "overall": compute_metrics(**overall_counts),
        "by_cwe": by_cwe,
    }


def format_markdown(report: Dict[str, object]) -> str:
    lines = [
        "# Upstream Juliet 1.3 Benchmark",
        "",
        f"Selected files: {report['selected_files']}",
        f"Evaluated bad/good functions: {report['evaluated_functions']}",
        f"Failed files: {len(report['failed_files'])}",
        "",
        "| CWE | TP | FP | TN | FN | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for cwe, metrics in report["by_cwe"].items():
        lines.append(
            f"| {cwe} | {metrics['tp']} | {metrics['fp']} | {metrics['tn']} | {metrics['fn']} | "
            f"{metrics['precision']:.4f} | {metrics['recall']:.4f} | {metrics['f1']:.4f} |"
        )
    overall = report["overall"]
    lines.extend([
        "",
        f"Overall precision: {overall['precision']:.4f}",
        f"Overall recall: {overall['recall']:.4f}",
        f"Overall F1: {overall['f1']:.4f}",
    ])
    return "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark C-GULL against upstream Juliet 1.3")
    parser.add_argument("suite_root", type=Path, help="Path containing Juliet's testcases/ directory")
    parser.add_argument("--cwe", action="append", default=[], help="CWE to include; may be repeated")
    parser.add_argument("--flow", action="append", default=[], help="Two-digit Juliet flow variant")
    parser.add_argument("--per-flow", type=int, default=2, help="Maximum entry files per CWE/flow")
    parser.add_argument("--all", action="store_true", help="Run every discoverable upstream entry file for the selected CWEs")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    suite_root = args.suite_root.resolve()
    if not (suite_root / "testcases").is_dir():
        raise SystemExit(f"Juliet suite root must contain testcases/: {suite_root}")
    cwes = [normalize_cwe(item) for item in args.cwe] or list(CWE_RULE_MAP)
    unknown = sorted(set(cwes) - set(CWE_RULE_MAP))
    if unknown:
        raise SystemExit(f"Unsupported CWE(s): {', '.join(unknown)}")
    if args.all and args.flow:
        raise SystemExit("--all cannot be combined with --flow")
    if args.per_flow < 1:
        raise SystemExit("--per-flow must be at least 1")

    if args.all:
        cases = select_all_cases(suite_root, cwes)
    else:
        flows = tuple(args.flow) or DEFAULT_FLOW_VARIANTS
        cases = select_stratified_cases(suite_root, cwes, flows, args.per_flow)

    if not cases:
        raise SystemExit("No Juliet cases matched the requested CWE/flow selection")
    report = run_benchmark(cases)
    rendered = (
        json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.format == "json"
        else format_markdown(report)
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
