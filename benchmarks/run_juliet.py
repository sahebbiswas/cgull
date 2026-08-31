#!/usr/bin/env python3
"""
Automated NIST Juliet Security Benchmark Runner for C-GULL.

Evaluates C-GULL detection quality (TP, FP, TN, FN, Precision, Recall, F1)
against vendored Juliet test-case subsets. Results are reported by CWE and by
rule so a regression in one rule cannot be hidden by another rule for the same
CWE.

Usage:
    python benchmarks/run_juliet.py [--ci] [--cwe CWE-476] [--category baseline]
                                     [--test-id TEST_ID] [--format text|json|markdown]
                                     [--min-precision 0.8] [--min-recall 0.8] [--min-f1 0.8]
                                     [--output report.json]
"""

import os
import sys
import re
import json
import argparse
from typing import Dict, List, Tuple, Any, Optional

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine, Issue

CWE_RULE_MAP = {
    "CWE-134": {"CGULL-002"},
    "CWE-190": {"CGULL-006"},
    "CWE-121": {"CGULL-007"},
    "CWE-122": {"CGULL-007"},
    "CWE-369": {"CGULL-034"},
    "CWE-476": {"CGULL-003", "CGULL-004"},
    "CWE-690": {"CGULL-003"},
    "CWE-416": {"CGULL-022"},
    "CWE-457": {"CGULL-021", "CGULL-023"},
}

CATEGORIES = [
    "baseline",
    "if/else",
    "nested conditionals",
    "loops",
    "switch",
    "fallthrough",
    "break / continue",
    "goto",
    "interprocedural cases",
]

CWES = list(CWE_RULE_MAP)


def extract_function_line_ranges(file_path: str) -> Dict[str, Tuple[int, int]]:
    """Extracts start and end 1-based line numbers for functions defined in file_path."""
    ranges: Dict[str, Tuple[int, int]] = {}
    if not os.path.exists(file_path):
        return ranges

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    current_fn = None
    start_line = 0
    brace_depth = 0
    fn_header_regex = re.compile(r'(?:static\s+)?void\s+([A-Za-z0-9_]+)\s*\(')

    for idx, line in enumerate(lines, 1):
        if not current_fn:
            m = fn_header_regex.search(line)
            if m:
                current_fn = m.group(1)
                start_line = idx
                brace_depth = 0

        if current_fn:
            for ch in line:
                if ch == '{':
                    brace_depth += 1
                elif ch == '}':
                    brace_depth -= 1
                    if brace_depth == 0 and start_line > 0:
                        ranges[current_fn] = (start_line, idx)
                        current_fn = None
                        start_line = 0
                        break
    return ranges


def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, Any]:
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def is_issue_cwe_match(issue: Issue, target_cwe: str, expected_rules: List[str]) -> bool:
    if target_cwe in issue.cwe_id:
        return True
    if issue.rule_id in expected_rules:
        return True
    rule_set = CWE_RULE_MAP.get(target_cwe, set())
    if issue.rule_id in rule_set:
        return True
    return False


def is_issue_from_source(issue_path: str, abs_source_path: str, manifest_dir: str) -> bool:
    if os.path.basename(issue_path) != os.path.basename(abs_source_path):
        return False
    real_abs = os.path.realpath(abs_source_path)
    real_issue = os.path.realpath(issue_path) if os.path.isabs(issue_path) else os.path.realpath(os.path.join(manifest_dir, issue_path))
    if real_issue == real_abs:
        return True
    if os.path.basename(real_issue) == os.path.basename(real_abs):
        return True
    return False


def run_juliet_benchmark(
    manifest_path: str,
    ci_only: bool = False,
    cwe_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
    test_id_filter: Optional[str] = None,
) -> Dict[str, Any]:
    if not os.path.isabs(manifest_path):
        manifest_path = os.path.join(REPO_ROOT, manifest_path)

    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"Juliet manifest file not found: {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    manifest_dir = os.path.dirname(manifest_path)
    scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    test_cases = manifest.get("test_cases", [])

    if ci_only:
        test_cases = [tc for tc in test_cases if tc.get("ci_subset", False)]

    if cwe_filter:
        cwe_filter_norm = cwe_filter.upper()
        if not cwe_filter_norm.startswith("CWE-"):
            cwe_filter_norm = f"CWE-{cwe_filter_norm}"
        test_cases = [tc for tc in test_cases if tc.get("cwe", "").upper() == cwe_filter_norm]

    if category_filter:
        category_filter_norm = category_filter.lower()
        test_cases = [tc for tc in test_cases if tc.get("category", "").lower() == category_filter_norm]

    if test_id_filter:
        test_id_filter_norm = test_id_filter.strip()
        test_cases = [tc for tc in test_cases if tc.get("id", "").strip() == test_id_filter_norm]

    cwe_stats = {cwe: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for cwe in CWES}
    # Populated from the selected oracle entries so filtered reports only show
    # rules that were actually evaluated.
    rule_stats: Dict[str, Dict[str, int]] = {}
    cat_stats = {cat: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for cat in CATEGORIES}
    overall_stats = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

    test_results = []
    failed_test_cases_count = 0

    for tc in test_cases:
        tc_id = tc["id"]
        cwe = tc["cwe"]
        category = tc["category"]
        rel_file = tc["file"]
        abs_file = os.path.join(manifest_dir, rel_file)

        fn_ranges = extract_function_line_ranges(abs_file)
        scan_res = scanner.scan_path(abs_file)

        # Check for scanner failure on this file
        is_scan_failed = (
            len(scan_res.failed_paths) > 0 or
            scan_res.files_failed > 0 or
            scan_res.get_overall_analysis_status() == "failed"
        )

        if is_scan_failed:
            failed_test_cases_count += 1
            test_results.append({
                "id": tc_id,
                "cwe": cwe,
                "category": category,
                "file": rel_file,
                "status": "failed",
                "scan_errors": [err.to_dict() for err in scan_res.scan_errors],
                "tp": 0,
                "fp": 0,
                "tn": 0,
                "fn": 0,
                "oracle_evaluations": [],
            })
            continue

        reported_issues: List[Issue] = scan_res.issues

        tc_tp = 0
        tc_fp = 0
        tc_tn = 0
        tc_fn = 0
        oracle_evals = []

        for o in tc.get("oracle", []):
            fn_name = o["function"]
            vulnerable = o["vulnerable"]
            expected_cwe = o["expected_cwe"]
            expected_rules = o.get("expected_rules", [])

            # Get explicit helper functions from oracle
            helpers = o.get("helper_functions", [])
            if isinstance(o.get("helper_function"), str):
                helpers.append(o["helper_function"])

            # Validate target function and helper functions exist in C file
            missing_fns = []
            if fn_name not in fn_ranges:
                missing_fns.append(fn_name)
            for h in helpers:
                if h not in fn_ranges:
                    missing_fns.append(h)

            if missing_fns:
                raise ValueError(
                    f"Testcase '{tc_id}' oracle references function(s) {missing_fns} "
                    f"that do not exist in source file '{rel_file}'."
                )

            fn_start, fn_end = fn_ranges[fn_name]
            helper_ranges = [fn_ranges[h] for h in helpers if h in fn_ranges]

            matching_issues = []
            matching_issues_by_rule: Dict[str, List[Issue]] = {}
            rules_to_evaluate = o.get("expected_rules") or sorted(CWE_RULE_MAP.get(expected_cwe, set()))
            for issue in reported_issues:
                # Require issue to originate from testcase source file
                if not is_issue_from_source(issue.file_path, abs_file, manifest_dir):
                    continue

                if is_issue_cwe_match(issue, expected_cwe, expected_rules):
                    in_main = (fn_start <= issue.line_number <= fn_end)
                    in_helper = any(h_start <= issue.line_number <= h_end for h_start, h_end in helper_ranges)
                    if in_main or in_helper:
                        matching_issues.append(issue)
                        if issue.rule_id in rules_to_evaluate:
                            matching_issues_by_rule.setdefault(issue.rule_id, []).append(issue)

            detected = len(matching_issues) > 0

            if vulnerable:
                if detected:
                    tc_tp += 1
                    outcome = "TP"
                else:
                    tc_fn += 1
                    outcome = "FN"
            else:
                if detected:
                    tc_fp += 1
                    outcome = "FP"
                else:
                    tc_tn += 1
                    outcome = "TN"

            oracle_evals.append({
                "function": fn_name,
                "vulnerable": vulnerable,
                "expected_cwe": expected_cwe,
                "detected": detected,
                "outcome": outcome,
                "matching_issues_count": len(matching_issues),
                "by_rule": {},
            })

            # A CWE may be implemented by more than one rule. Evaluate each
            # rule independently, rather than treating a finding from any
            # sibling rule as a detection for all of them.
            for rule_id in rules_to_evaluate:
                rule_detected = bool(matching_issues_by_rule.get(rule_id))
                if vulnerable:
                    rule_outcome = "TP" if rule_detected else "FN"
                else:
                    rule_outcome = "FP" if rule_detected else "TN"

                rule_stats.setdefault(rule_id, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
                rule_stats[rule_id][rule_outcome.lower()] += 1
                oracle_evals[-1]["by_rule"][rule_id] = {
                    "detected": rule_detected,
                    "outcome": rule_outcome,
                    "matching_issues_count": len(matching_issues_by_rule.get(rule_id, [])),
                }

        cwe_entry = cwe_stats.setdefault(cwe, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        cat_entry = cat_stats.setdefault(category, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})

        for key, val in [("tp", tc_tp), ("fp", tc_fp), ("tn", tc_tn), ("fn", tc_fn)]:
            cwe_entry[key] += val
            cat_entry[key] += val
            overall_stats[key] += val

        test_results.append({
            "id": tc_id,
            "cwe": cwe,
            "category": category,
            "file": rel_file,
            "status": "success",
            "tp": tc_tp,
            "fp": tc_fp,
            "tn": tc_tn,
            "fn": tc_fn,
            "oracle_evaluations": oracle_evals,
        })

    cwe_metrics = {cwe: compute_metrics(s["tp"], s["fp"], s["tn"], s["fn"]) for cwe, s in cwe_stats.items()}
    rule_metrics = {rule_id: compute_metrics(s["tp"], s["fp"], s["tn"], s["fn"]) for rule_id, s in rule_stats.items()}
    cat_metrics = {cat: compute_metrics(s["tp"], s["fp"], s["tn"], s["fn"]) for cat, s in cat_stats.items()}
    overall_metrics = compute_metrics(overall_stats["tp"], overall_stats["fp"], overall_stats["tn"], overall_stats["fn"])

    return {
        "suite": manifest.get("suite", "Juliet Benchmark"),
        "version": manifest.get("version", "1.0"),
        "total_test_cases_evaluated": len(test_cases),
        "failed_test_cases_count": failed_test_cases_count,
        "filters": {
            "ci_only": ci_only,
            "cwe": cwe_filter,
            "category": category_filter,
            "test_id": test_id_filter,
        },
        "overall": overall_metrics,
        "by_cwe": cwe_metrics,
        "by_rule": rule_metrics,
        "by_category": cat_metrics,
        "test_cases": test_results,
    }


def format_text_report(results: Dict[str, Any]) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append(f"C-GULL Juliet Benchmark Results ({results['suite']} v{results['version']})")
    lines.append("=" * 78)
    lines.append(f"Evaluated Test Cases: {results['total_test_cases_evaluated']} (Failed Scans: {results['failed_test_cases_count']})")
    ov = results["overall"]
    lines.append(f"Overall Metrics: TP={ov['tp']}, FP={ov['fp']}, TN={ov['tn']}, FN={ov['fn']} | Precision={ov['precision']:.4f}, Recall={ov['recall']:.4f}, F1={ov['f1']:.4f}")
    lines.append("-" * 78)

    lines.append("\nResults by CWE:")
    lines.append(f"{'CWE ID':<12} {'TP':<6} {'FP':<6} {'TN':<6} {'FN':<6} {'Precision':<11} {'Recall':<11} {'F1':<11}")
    lines.append("-" * 78)
    for cwe, m in results["by_cwe"].items():
        lines.append(f"{cwe:<12} {m['tp']:<6} {m['fp']:<6} {m['tn']:<6} {m['fn']:<6} {m['precision']:<11.4f} {m['recall']:<11.4f} {m['f1']:<11.4f}")

    lines.append("\nResults by Rule:")
    lines.append(f"{'Rule ID':<12} {'TP':<6} {'FP':<6} {'TN':<6} {'FN':<6} {'Precision':<11} {'Recall':<11} {'F1':<11}")
    lines.append("-" * 78)
    for rule_id, m in results["by_rule"].items():
        lines.append(f"{rule_id:<12} {m['tp']:<6} {m['fp']:<6} {m['tn']:<6} {m['fn']:<6} {m['precision']:<11.4f} {m['recall']:<11.4f} {m['f1']:<11.4f}")

    lines.append("\nResults by Control-Flow Category:")
    lines.append(f"{'Category':<24} {'TP':<6} {'FP':<6} {'TN':<6} {'FN':<6} {'Precision':<11} {'Recall':<11} {'F1':<11}")
    lines.append("-" * 78)
    for cat, m in results["by_category"].items():
        lines.append(f"{cat:<24} {m['tp']:<6} {m['fp']:<6} {m['tn']:<6} {m['fn']:<6} {m['precision']:<11.4f} {m['recall']:<11.4f} {m['f1']:<11.4f}")

    lines.append("=" * 78)
    return "\n".join(lines)


def format_markdown_report(results: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"# C-GULL Juliet Benchmark Results ({results['suite']} v{results['version']})\n")
    lines.append(f"**Evaluated Test Cases**: {results['total_test_cases_evaluated']} (Failed Scans: {results['failed_test_cases_count']})\n")

    ov = results["overall"]
    lines.append("## Overall Metrics\n")
    lines.append(f"- **TP**: {ov['tp']}")
    lines.append(f"- **FP**: {ov['fp']}")
    lines.append(f"- **TN**: {ov['tn']}")
    lines.append(f"- **FN**: {ov['fn']}")
    lines.append(f"- **Precision**: {ov['precision']:.4f}")
    lines.append(f"- **Recall**: {ov['recall']:.4f}")
    lines.append(f"- **F1 Score**: {ov['f1']:.4f}\n")

    lines.append("## Results by CWE\n")
    lines.append("| CWE ID | TP | FP | TN | FN | Precision | Recall | F1 Score |")
    lines.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|")
    for cwe, m in results["by_cwe"].items():
        lines.append(f"| {cwe} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} |")

    lines.append("\n## Results by Rule\n")
    lines.append("| Rule ID | TP | FP | TN | FN | Precision | Recall | F1 Score |")
    lines.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|")
    for rule_id, m in results["by_rule"].items():
        lines.append(f"| {rule_id} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} |")

    lines.append("\n## Results by Control-Flow Category\n")
    lines.append("| Category | TP | FP | TN | FN | Precision | Recall | F1 Score |")
    lines.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|")
    for cat, m in results["by_category"].items():
        lines.append(f"| {cat} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} |")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Automated NIST Juliet Security Benchmark Runner for C-GULL")
    parser.add_argument("--manifest", type=str, default="benchmarks/juliet/manifest.json", help="Path to Juliet benchmark manifest JSON file")
    parser.add_argument("--ci", action="store_true", help="Run focused subset for CI pipeline")
    parser.add_argument("--cwe", type=str, help="Filter benchmark by specific CWE (e.g., CWE-476)")
    parser.add_argument("--category", type=str, help="Filter benchmark by control-flow category (e.g., baseline, if/else)")
    parser.add_argument("--test-id", type=str, help="Filter benchmark by individual Juliet test ID")
    parser.add_argument("--format", type=str, choices=["text", "json", "markdown"], default="text", help="Output format")
    parser.add_argument("--min-precision", type=float, default=0.0, help="Minimum required overall Precision score")
    parser.add_argument("--min-recall", type=float, default=0.0, help="Minimum required overall Recall score")
    parser.add_argument("--min-f1", type=float, default=0.0, help="Minimum required overall F1 score")
    parser.add_argument("--output", type=str, help="Write output report to specified file")

    args = parser.parse_args()

    results = run_juliet_benchmark(
        manifest_path=args.manifest,
        ci_only=args.ci,
        cwe_filter=args.cwe,
        category_filter=args.category,
        test_id_filter=args.test_id,
    )

    if args.format == "json":
        report_str = json.dumps(results, indent=2)
    elif args.format == "markdown":
        report_str = format_markdown_report(results)
    else:
        report_str = format_text_report(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_str + "\n")
        print(f"Report written to {args.output}")
    else:
        print(report_str)

    # Check for scan failures or quality threshold violations
    failed_scans = results.get("failed_test_cases_count", 0)
    ov = results.get("overall", {})
    precision = ov.get("precision", 0.0)
    recall = ov.get("recall", 0.0)
    f1 = ov.get("f1", 0.0)

    has_error = False

    if failed_scans > 0:
        print(f"ERROR: {failed_scans} test case scan(s) failed during execution.", file=sys.stderr)
        has_error = True

    if precision < args.min_precision:
        print(f"ERROR: Precision ({precision:.4f}) is below minimum threshold ({args.min_precision:.4f}).", file=sys.stderr)
        has_error = True

    if recall < args.min_recall:
        print(f"ERROR: Recall ({recall:.4f}) is below minimum threshold ({args.min_recall:.4f}).", file=sys.stderr)
        has_error = True

    if f1 < args.min_f1:
        print(f"ERROR: F1 Score ({f1:.4f}) is below minimum threshold ({args.min_f1:.4f}).", file=sys.stderr)
        has_error = True

    if has_error:
        sys.exit(1)


if __name__ == "__main__":
    main()
