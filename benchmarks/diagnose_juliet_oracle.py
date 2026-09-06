#!/usr/bin/env python3
"""Diagnose lexical bad/good oracle attribution for split-file Juliet cases.

Issue #327 observed exact TP/FP and TN/FN symmetry for CWE-134 and CWE-369.
This diagnostic intentionally does not run C-GULL. It checks whether the generic
upstream benchmark's lexical function-range oracle can even observe the sink for
Juliet flow-54 entry files, whose template moves the sink into sibling source
files.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Sequence

TARGETS = {
    "CWE-134": "CWE134_Uncontrolled_Format_String",
    "CWE-369": "CWE369_Divide_by_Zero",
}
ENTRY_RE = re.compile(r"_54a\.(?:c|cpp)$", re.IGNORECASE)
EXTERNAL_SINK_RE = re.compile(r"\b[A-Za-z_]\w*_54b_(?:badSink|good\w*Sink)\s*\(")
LOCAL_SINK_HINTS = {
    "CWE-134": re.compile(r"\b(?:printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf)\s*\("),
    "CWE-369": re.compile(r"(?:/|%)\s*[A-Za-z_(]"),
}


def _cwe_directory(root: Path, dirname: str) -> Path:
    direct = root / "testcases" / dirname
    if direct.is_dir():
        return direct
    matches = sorted((root / "testcases").glob(f"{dirname}*"))
    if not matches:
        raise FileNotFoundError(f"Unable to locate {dirname} below {root / 'testcases'}")
    return matches[0]


def select_flow54_entries(root: Path, cwe: str, limit: int) -> List[Path]:
    directory = _cwe_directory(root, TARGETS[cwe])
    entries = [p for p in sorted(directory.rglob("*")) if p.is_file() and ENTRY_RE.search(p.name)]
    return entries[:limit]


def inspect_entry(path: Path, cwe: str) -> Dict[str, object]:
    source = path.read_text(encoding="utf-8", errors="replace")
    external_sink_calls = sorted(set(EXTERNAL_SINK_RE.findall(source)))
    # Flow-54 entry files may contain platform/helper arithmetic unrelated to the
    # CWE. The decisive signal is the explicit call into the 54b sink stage.
    has_external_sink_stage = bool(EXTERNAL_SINK_RE.search(source))
    has_local_sink_hint = bool(LOCAL_SINK_HINTS[cwe].search(source))
    return {
        "file": str(path),
        "has_external_sink_stage": has_external_sink_stage,
        "has_local_sink_hint": has_local_sink_hint,
        "lexical_oracle_can_own_sink": not has_external_sink_stage,
        "external_sink_calls": external_sink_calls,
    }


def run_diagnostic(root: Path, per_cwe: int = 25) -> Dict[str, object]:
    samples: Dict[str, List[Dict[str, object]]] = {}
    totals = {"sampled": 0, "split_sink": 0, "lexical_oracle_can_own_sink": 0}
    warnings: List[str] = []
    for cwe in TARGETS:
        try:
            entries = select_flow54_entries(root, cwe, per_cwe)
        except FileNotFoundError as exc:
            entries = []
            warnings.append(str(exc))
        if len(entries) < per_cwe:
            warnings.append(
                f"{cwe}: requested {per_cwe} flow-54 entry files, found {len(entries)}"
            )
        inspected = [inspect_entry(path, cwe) for path in entries]
        samples[cwe] = inspected
        totals["sampled"] += len(inspected)
        totals["split_sink"] += sum(bool(item["has_external_sink_stage"]) for item in inspected)
        totals["lexical_oracle_can_own_sink"] += sum(
            bool(item["lexical_oracle_can_own_sink"]) for item in inspected
        )
    return {
        "schema_version": 1,
        "purpose": "issue-327-juliet-oracle-attribution",
        "per_cwe_limit": per_cwe,
        "totals": totals,
        "by_cwe": samples,
        "warnings": warnings,
        "finding": (
            "generic lexical bad/good function ranges are not a valid oracle for split-file flow-54 "
            "cases when the CWE sink is delegated to sibling 54b source files"
        ),
    }


def format_markdown(report: Dict[str, object]) -> str:
    totals = report["totals"]
    lines = [
        "# Juliet Oracle Attribution Diagnostic",
        "",
        f"Sampled flow-54 entry files: {totals['sampled']}",
        f"Entries delegating to sibling 54b sink stages: {totals['split_sink']}",
        f"Entries whose lexical wrapper range can own the sink: {totals['lexical_oracle_can_own_sink']}",
        "",
        "## Finding",
        "",
        str(report["finding"]),
        "",
        "The upstream benchmark currently scans each entry file independently and attributes findings only by line range inside bad/good wrapper functions. For these split-file cases that attribution cannot observe the sink by construction, so TP/FP/TN/FN symmetry from the generic oracle must not be treated as rule-quality evidence until multi-file attribution is fixed.",
        "",
    ]
    warnings = report.get("warnings", [])
    if warnings:
        lines.extend(["## Sampling warnings", ""])
        lines.extend(f"- {warning}" for warning in warnings)
        lines.append("")
    for cwe, items in report["by_cwe"].items():
        split = sum(bool(item["has_external_sink_stage"]) for item in items)
        lines.append(f"- {cwe}: {split}/{len(items)} sampled entry files delegate to a sibling sink stage")
    return "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Diagnose Juliet split-file oracle attribution")
    parser.add_argument("suite_root", type=Path)
    parser.add_argument("--per-cwe", type=int, default=25)
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.per_cwe < 1:
        raise SystemExit("--per-cwe must be at least 1")
    report = run_diagnostic(args.suite_root.resolve(), args.per_cwe)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n" if args.format == "json" else format_markdown(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    for warning in report.get("warnings", []):
        print(f"warning: {warning}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
