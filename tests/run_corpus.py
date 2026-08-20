#!/usr/bin/env python3
"""
Independent Security Rule Behavioral Corpus Runner.

Scans C files in `tests/rules/CGULL-xxx/` and verifies that scanner findings
match exact line annotations (`// expect: CGULL-xxx`).

Usage:
    python3 tests/run_corpus.py [--rule CGULL-003] [--verbose]
"""

import sys
import os
import re
import argparse
from typing import Dict, List, Set, Tuple

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cgull.engine import CGullScanner
from cgull.rules import get_rule_by_id, RULE_REGISTRY
from cgull.models import AnalysisEngine, Issue


EXPECT_REGEX = re.compile(r'(?://|/\*)\s*expect:\s*(CGULL-\d{3})', re.IGNORECASE)


def parse_expectations(file_path: str) -> Dict[int, Set[str]]:
    """
    Parses a C file and returns a map of line_number -> set of expected rule_ids.
    Example line comment: `char *p = malloc(16); // expect: CGULL-003`
    """
    expectations: Dict[int, Set[str]] = {}
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    for line_idx, line_content in enumerate(lines, 1):
        for m in EXPECT_REGEX.finditer(line_content):
            rule_id = m.group(1).upper()
            expectations.setdefault(line_idx, set()).add(rule_id)

    return expectations


def run_corpus_scan(
    rules_dir: str,
    target_rule_id: str = None,
    verbose: bool = False,
    min_behavioral_coverage: float = 0.0
) -> Tuple[bool, str]:
    """
    Runs corpus verification against tests/rules/.
    Optionally verifies that Rule Behavioral Coverage meets or exceeds min_behavioral_coverage.
    Returns (success: bool, report_text: str).
    """
    if not os.path.exists(rules_dir):
        return False, f"Corpus rules directory not found: {rules_dir}"

    rule_folders = [
        d for d in os.listdir(rules_dir)
        if os.path.isdir(os.path.join(rules_dir, d)) and d.startswith("CGULL-")
    ]
    rule_folders.sort()

    if target_rule_id:
        target_rule_id = target_rule_id.upper()
        rule_folders = [d for d in rule_folders if d == target_rule_id]
        if not rule_folders:
            return False, f"Rule ID '{target_rule_id}' not found in corpus directory {rules_dir}"

    total_files = 0
    total_expected = 0
    total_matched = 0
    total_missing = 0
    total_unexpected = 0
    failures: List[str] = []
    log_lines: List[str] = []

    log_lines.append("=" * 70)
    log_lines.append("C-GULL Security Rule Behavioral Corpus Verification")
    log_lines.append("=" * 70)

    for rule_id in rule_folders:
        rule_dir = os.path.join(rules_dir, rule_id)
        if rule_id not in RULE_REGISTRY:
            log_lines.append(f"WARNING: Rule ID '{rule_id}' directory exists but rule is not in registry. Skipping.")
            continue

        rule_instance = get_rule_by_id(rule_id)
        scanner = CGullScanner(rules=[rule_instance], engine_mode=AnalysisEngine.HYBRID)

        c_files = [
            f for f in os.listdir(rule_dir)
            if f.endswith(".c")
        ]
        c_files.sort()

        log_lines.append(f"\nRule [{rule_id}] - {rule_instance.name}")

        for c_file in c_files:
            file_path = os.path.join(rule_dir, c_file)
            rel_file_path = os.path.relpath(file_path, REPO_ROOT)
            total_files += 1

            expectations = parse_expectations(file_path)
            scan_result = scanner.scan_path(file_path)
            reported_issues: List[Issue] = scan_result.issues

            reported_by_line: Dict[int, Set[str]] = {}
            for issue in reported_issues:
                reported_by_line.setdefault(issue.line_number, set()).add(issue.rule_id)

            # Check for expected findings
            file_missing = 0
            file_expected = 0
            for line_no, exp_rules in expectations.items():
                for exp_rule in exp_rules:
                    file_expected += 1
                    total_expected += 1
                    if exp_rule in reported_by_line.get(line_no, set()):
                        total_matched += 1
                    else:
                        file_missing += 1
                        total_missing += 1
                        msg = f"  FAIL: {rel_file_path}:{line_no} - Expected {exp_rule} but no finding was reported."
                        failures.append(msg)
                        log_lines.append(msg)

            # Check for unexpected findings
            file_unexpected = 0
            for line_no, rep_rules in reported_by_line.items():
                for rep_rule in rep_rules:
                    if rep_rule not in expectations.get(line_no, set()):
                        file_unexpected += 1
                        total_unexpected += 1
                        msg = f"  FAIL: {rel_file_path}:{line_no} - Unexpected finding {rep_rule} reported without expectation."
                        failures.append(msg)
                        log_lines.append(msg)

            if file_missing == 0 and file_unexpected == 0:
                if verbose or True:
                    log_lines.append(f"  PASS: {c_file} ({file_expected} expected findings verified)")

    total_registered_rules = len(RULE_REGISTRY)
    valid_evaluated_rules = [r for r in rule_folders if r in RULE_REGISTRY]
    evaluated_rules_count = len(valid_evaluated_rules)
    behavioral_coverage_pct = (evaluated_rules_count / total_registered_rules * 100.0) if total_registered_rules > 0 else 0.0

    coverage_failed = False
    if target_rule_id is None and min_behavioral_coverage > 0:
        if behavioral_coverage_pct < min_behavioral_coverage:
            coverage_failed = True
            failures.append(
                f"Rule Behavioral Coverage ({behavioral_coverage_pct:.2f}%) is below minimum threshold ({min_behavioral_coverage:.2f}%)."
            )

    log_lines.append("\n" + "=" * 70)
    log_lines.append("Corpus Verification Summary:")
    log_lines.append(f"  Registered Rules       : {total_registered_rules}")
    log_lines.append(f"  Rule Suites Evaluated  : {evaluated_rules_count}")
    log_lines.append(f"  Rule Behavioral Coverage: {behavioral_coverage_pct:.2f}%")
    if min_behavioral_coverage > 0 and target_rule_id is None:
        log_lines.append(f"  Required Min Coverage  : {min_behavioral_coverage:.2f}%")
    log_lines.append(f"  Total Files Scanned    : {total_files}")
    log_lines.append(f"  Expected Findings      : {total_expected}")
    log_lines.append(f"  Matched Findings       : {total_matched}")
    log_lines.append(f"  Missing Findings (FN)  : {total_missing}")
    log_lines.append(f"  Unexpected Findings(FP): {total_unexpected}")
    log_lines.append("=" * 70)

    success = (total_missing == 0 and total_unexpected == 0 and total_files > 0 and not coverage_failed)
    if success:
        log_lines.append("SUCCESS: All behavioral corpus tests and coverage requirements passed!")
    else:
        if coverage_failed:
            log_lines.append(f"FAILURE: Rule Behavioral Coverage ({behavioral_coverage_pct:.2f}%) did not meet required threshold ({min_behavioral_coverage:.2f}%).")
        else:
            log_lines.append("FAILURE: Corpus verification failed due to discrepancies above.")

    return success, "\n".join(log_lines)


def main():
    parser = argparse.ArgumentParser(description="Run C-GULL Security Rule Behavioral Corpus")
    parser.add_argument("--rule", type=str, help="Specific rule ID to run (e.g. CGULL-003)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--min-coverage", type=float, default=0.0, help="Minimum required Rule Behavioral Coverage percentage")
    args = parser.parse_args()

    rules_dir = os.path.join(REPO_ROOT, "tests", "rules")
    success, report = run_corpus_scan(
        rules_dir,
        target_rule_id=args.rule,
        verbose=args.verbose,
        min_behavioral_coverage=args.min_coverage
    )
    print(report)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
