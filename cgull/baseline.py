"""
Baseline/diff support for C-GULL.

Lets a scan be filtered down to only *new* findings relative to a
previously-saved baseline report -- the missing piece for adopting a
scanner on an existing, imperfect codebase: `--fail-on-high` alone fails
on every pre-existing issue, which usually makes CI enforcement a
non-starter until the whole codebase is already clean.

Workflow:
    # Snapshot current findings as the accepted baseline
    cgull scan src/ --update-baseline baseline.json

    # Later, in CI: only fail on issues introduced since the baseline
    cgull scan src/ --baseline baseline.json --fail-on-high

A baseline file is just an ordinary C-GULL JSON report (the same format
`--format json` produces) -- there is no separate baseline format, so any
previous JSON report can be reused as a baseline directly.
"""

import json
from collections import Counter
from typing import List, Tuple

from .models import ScanResult, Issue, Severity


class BaselineError(Exception):
    """Raised when a baseline file can't be read or doesn't look like a C-GULL report."""


def load_baseline_fingerprints(path: str) -> Counter:
    """
    Loads a baseline JSON report and returns a Counter of
    fingerprint -> occurrence count.

    A Counter (multiset) rather than a plain set is used deliberately: if
    a rule matches textually-identical code at two different call sites,
    both share a fingerprint (see utils.compute_issue_fingerprint). Using
    a set would mean "one of them got fixed" is invisible -- as soon as
    at least one instance is in the baseline, both would be silently
    treated as pre-existing forever. A Counter lets `apply_baseline`
    correctly recognize that a *second* occurrence beyond what the
    baseline had is genuinely new.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise BaselineError(f"Baseline file not found: {path}")
    except json.JSONDecodeError as e:
        raise BaselineError(f"Baseline file '{path}' is not valid JSON: {e}")

    issues = data.get("issues")
    if issues is None:
        raise BaselineError(
            f"'{path}' does not look like a C-GULL JSON report (no 'issues' key). "
            "Baseline files must be generated with 'cgull scan ... --format json' "
            "or 'cgull scan ... --update-baseline <path>'."
        )

    counts: Counter = Counter()
    for issue in issues:
        fp = issue.get("fingerprint")
        if fp:
            counts[fp] += 1
    return counts


def apply_baseline(result: ScanResult, baseline_counts: Counter) -> ScanResult:
    """
    Returns a NEW ScanResult containing only the issues from `result` that
    are not already accounted for in `baseline_counts` -- i.e. genuinely
    new findings introduced since the baseline was captured.

    Also computes `baseline_resolved_count`: how many baseline findings no
    longer appear at all in the current scan (positive signal worth
    surfacing, not just the new-issue count).
    """
    remaining_baseline = Counter(baseline_counts)
    new_issues: List[Issue] = []
    current_counts: Counter = Counter()

    for issue in result.issues:
        current_counts[issue.fingerprint] += 1
        if remaining_baseline.get(issue.fingerprint, 0) > 0:
            remaining_baseline[issue.fingerprint] -= 1
            continue
        new_issues.append(issue)

    resolved_count = 0
    for fp, baseline_n in baseline_counts.items():
        resolved_count += max(0, baseline_n - current_counts.get(fp, 0))

    high = sum(1 for i in new_issues if i.impact == Severity.HIGH)
    medium = sum(1 for i in new_issues if i.impact == Severity.MEDIUM)
    low = sum(1 for i in new_issues if i.impact == Severity.LOW)

    return ScanResult(
        target_path=result.target_path,
        scanned_files_count=result.scanned_files_count,
        total_lines_of_code=result.total_lines_of_code,
        total_issues_count=len(new_issues),
        high_severity_count=high,
        medium_severity_count=medium,
        low_severity_count=low,
        scan_duration_seconds=result.scan_duration_seconds,
        timestamp=result.timestamp,
        issues=new_issues,
        file_summaries=result.file_summaries,
        ignored_paths=result.ignored_paths,
        failed_paths=result.failed_paths,
        files_discovered=result.files_discovered,
        files_analyzed=result.files_analyzed,
        files_ignored=result.files_ignored,
        files_failed=result.files_failed,
        analysis_status_counts=result.analysis_status_counts,
        overall_parser_status=result.overall_parser_status,
        overall_analysis_status=result.overall_analysis_status,
        rules_applied=result.rules_applied,
        is_baseline_filtered=True,
        baseline_new_count=len(new_issues),
        baseline_resolved_count=resolved_count,
        baseline_total_before_filter=result.total_issues_count,
    )
