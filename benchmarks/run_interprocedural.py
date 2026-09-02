#!/usr/bin/env python3
"""Run the focused interprocedural regression corpus and report baseline metrics."""

import argparse
import json
import os
import sys
from typing import Any, Dict, Iterable, List


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmarks.security_fact_support import (
    build_security_context,
    build_security_models,
)
from cgull.cfg import build_cfg, find_function_def
from cgull.cfg.security_dataflow import analyze_security_dataflow, analyze_security_summaries
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import RULE_REGISTRY, get_rule_by_id


DEFAULT_MANIFEST = os.path.join(
    REPO_ROOT, "benchmarks", "interprocedural", "manifest.json"
)
SECURITY_FACT_MANIFEST = "security_facts.json"
METRIC_KEYS = (
    "cases",
    "expected_positives",
    "expected_negatives",
    "tp",
    "fp",
    "tn",
    "fn",
    "known_gaps",
)


def _empty_metrics() -> Dict[str, int]:
    return {key: 0 for key in METRIC_KEYS}


def _record_case(
    metrics: Dict[str, int],
    vulnerable: bool,
    detected: bool,
    known_gap: bool,
) -> str:
    metrics["cases"] += 1
    metrics["expected_positives" if vulnerable else "expected_negatives"] += 1
    metrics["known_gaps"] += int(known_gap)
    if vulnerable:
        outcome = "tp" if detected else "fn"
    else:
        outcome = "fp" if detected else "tn"
    metrics[outcome] += 1
    return outcome.upper()


def _collect_metrics(
    cases: Iterable[Dict[str, Any]], detected_field: str
) -> Dict[str, Any]:
    overall = _empty_metrics()
    by_rule: Dict[str, Dict[str, int]] = {}
    by_family: Dict[str, Dict[str, int]] = {}
    by_scenario: Dict[str, Dict[str, int]] = {}

    for case in cases:
        vulnerable = case["vulnerable"]
        detected = case[detected_field]
        known_gap = (
            case.get("status") == "known_gap"
            if detected_field == "detected"
            else "known_gap" in case
        )
        _record_case(overall, vulnerable, detected, known_gap)
        _record_case(
            by_rule.setdefault(case["rule_id"], _empty_metrics()),
            vulnerable,
            detected,
            known_gap,
        )
        _record_case(
            by_family.setdefault(case["family"], _empty_metrics()),
            vulnerable,
            detected,
            known_gap,
        )
        _record_case(
            by_scenario.setdefault(case["scenario"], _empty_metrics()),
            vulnerable,
            detected,
            known_gap,
        )

    return {
        "overall": overall,
        "by_rule": {key: by_rule[key] for key in sorted(by_rule)},
        "by_family": {key: by_family[key] for key in sorted(by_family)},
        "by_scenario": {key: by_scenario[key] for key in sorted(by_scenario)},
    }


def _validate_manifest(manifest: Dict[str, Any], manifest_path: str) -> None:
    cases = manifest.get("cases", [])
    if len(cases) < 20:
        raise ValueError("Interprocedural corpus must contain at least 20 cases")

    manifest_dir = os.path.dirname(manifest_path)
    milestone_path = manifest.get("milestone", "").split("#", 1)[0]
    if not milestone_path or not os.path.isfile(
        os.path.normpath(os.path.join(manifest_dir, milestone_path))
    ):
        raise ValueError("Manifest must link to the interprocedural milestone")
    case_ids = [case.get("id") for case in cases]
    if any(not case_id for case_id in case_ids):
        raise ValueError("Every interprocedural case needs a non-empty id")
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("Interprocedural case ids must be unique")

    required_fields = {
        "file",
        "scenario",
        "family",
        "rule_id",
        "vulnerable",
        "baseline_detected",
    }
    scenario_expectations: Dict[str, set] = {}
    family_expectations: Dict[str, set] = {}

    for case in cases:
        missing = sorted(required_fields - set(case))
        if missing:
            raise ValueError(f"Case '{case['id']}' is missing fields: {missing}")
        if not isinstance(case["vulnerable"], bool):
            raise ValueError(f"Case '{case['id']}' vulnerable must be boolean")
        if not isinstance(case["baseline_detected"], bool):
            raise ValueError(
                f"Case '{case['id']}' baseline_detected must be boolean"
            )
        if case["rule_id"] not in RULE_REGISTRY:
            raise ValueError(
                f"Case '{case['id']}' references unknown rule {case['rule_id']}"
            )

        fixture_path = os.path.join(manifest_dir, case["file"])
        if not os.path.isfile(fixture_path):
            raise ValueError(
                f"Case '{case['id']}' fixture does not exist: {case['file']}"
            )

        is_gap = case["baseline_detected"] != case["vulnerable"]
        if is_gap != ("known_gap" in case):
            raise ValueError(
                f"Case '{case['id']}' must mark exactly baseline mismatches as known gaps"
            )
        if is_gap:
            gap = case["known_gap"]
            if not gap.get("reason", "").strip():
                raise ValueError(f"Case '{case['id']}' known gap needs a reason")
            tracking = gap.get("tracking", "")
            tracking_path = tracking.split("#", 1)[0]
            if tracking_path != milestone_path:
                raise ValueError(
                    f"Case '{case['id']}' known gap must link to the milestone"
                )

        scenario_expectations.setdefault(case["scenario"], set()).add(
            case["vulnerable"]
        )
        family_expectations.setdefault(case["family"], set()).add(
            case["vulnerable"]
        )

    for scenario in manifest.get("required_scenarios", []):
        if scenario_expectations.get(scenario) != {False, True}:
            raise ValueError(
                f"Scenario '{scenario}' needs at least one safe and unsafe case"
            )
    for family in manifest.get("required_families", []):
        if family_expectations.get(family) != {False, True}:
            raise ValueError(
                f"Family '{family}' needs at least one safe and unsafe case"
            )

    calculated_baseline = _collect_metrics(cases, "baseline_detected")
    if calculated_baseline != manifest.get("baseline"):
        raise ValueError("Recorded baseline metrics do not match manifest cases")


def _security_models():
    return build_security_models()


def _security_context(source: str):
    return build_security_context(source)


def _run_security_fact_cases(manifest_dir: str) -> Dict[str, Any]:
    path = os.path.join(manifest_dir, SECURITY_FACT_MANIFEST)
    with open(path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    models = _security_models()
    results: List[Dict[str, Any]] = []
    failures: List[str] = []

    for case in manifest.get("cases", []):
        fixture_path = os.path.join(manifest_dir, case["file"])
        with open(fixture_path, "r", encoding="utf-8") as fixture:
            ctx = _security_context(fixture.read())
        summaries = analyze_security_summaries(ctx, models)
        actual: Dict[str, Any] = {}

        if "summary_function" in case:
            summary = summaries[case["summary_function"]]
            actual["return_params"] = sorted(summary.return_from_params)
            passed = actual["return_params"] == case.get("expected_return_params", [])
        else:
            function = case["function"]
            funcdef = find_function_def(ctx.pycparser_ast, function)
            if funcdef is None:
                failures.append(f"{case['id']}: function '{function}' not found")
                results.append({**case, "actual": actual, "status": "regression"})
                continue
            cfg = build_cfg(funcdef)
            facts = analyze_security_dataflow(cfg, models, summaries)
            sink_node = next(
                (
                    node
                    for node in cfg.nodes.values()
                    if any(call.direct_callee == case["sink"] for call in node.calls)
                ),
                None,
            )
            if sink_node is None:
                failures.append(
                    f"{case['id']}: sink '{case['sink']}' not found in function '{function}'"
                )
                results.append({**case, "actual": actual, "status": "regression"})
                continue
            actual["provenance"] = facts.query_provenance(
                case["location"], sink_node.node_id
            ).value
            actual["validations"] = sorted(
                prop.value
                for prop in facts.query_validation_properties(
                    case["location"], sink_node.node_id
                )
            )
            passed = (
                actual["provenance"] == case["expected_provenance"]
                and actual["validations"] == sorted(case.get("expected_validations", []))
            )

        status = "pass" if passed else "regression"
        if not passed:
            failures.append(f"{case['id']}: expected security facts did not match")
        results.append({**case, "actual": actual, "status": status})

    passed_count = sum(case["status"] == "pass" for case in results)
    return {
        "version": manifest.get("version", "1.0"),
        "metrics": {
            "cases": len(results),
            "passed": passed_count,
            "failed": len(results) - passed_count,
        },
        "failures": failures,
        "cases": results,
    }


def run_interprocedural_corpus(
    manifest_path: str = DEFAULT_MANIFEST,
) -> Dict[str, Any]:
    if not os.path.isabs(manifest_path):
        manifest_path = os.path.join(REPO_ROOT, manifest_path)
    manifest_path = os.path.normpath(manifest_path)

    with open(manifest_path, "r", encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)
    _validate_manifest(manifest, manifest_path)

    manifest_dir = os.path.dirname(manifest_path)
    results: List[Dict[str, Any]] = []
    failures: List[str] = []

    for case in manifest["cases"]:
        rule_id = case["rule_id"]
        scanner = CGullScanner(
            rules=[get_rule_by_id(rule_id)],
            engine_mode=AnalysisEngine.HYBRID,
        )
        fixture_path = os.path.join(manifest_dir, case["file"])
        scan_result = scanner.scan_path(fixture_path)
        scan_failed = bool(
            scan_result.failed_paths
            or scan_result.files_failed
            or scan_result.get_overall_analysis_status() == "failed"
        )
        matching_issues = [
            issue for issue in scan_result.issues if issue.rule_id == rule_id
        ]
        detected = bool(matching_issues)
        known_gap = case.get("known_gap")

        if scan_failed:
            status = "scan_failed"
            failures.append(f"{case['id']}: fixture scan failed")
        elif known_gap:
            status = "resolved_known_gap" if detected == case["vulnerable"] else "known_gap"
        elif detected != case["baseline_detected"]:
            status = "regression"
            failures.append(
                f"{case['id']}: expected detected={case['baseline_detected']}, "
                f"got detected={detected}"
            )
        else:
            status = "pass"

        results.append(
            {
                **case,
                "detected": detected,
                "status": status,
                "finding_count": len(matching_issues),
                "scan_errors": [error.to_dict() for error in scan_result.scan_errors],
            }
        )

    current_metrics = _collect_metrics(results, "detected")
    security_facts = _run_security_fact_cases(manifest_dir)
    failures.extend(security_facts["failures"])
    return {
        "suite": manifest["suite"],
        "version": manifest["version"],
        "success": not failures,
        "failures": failures,
        "recorded_baseline": manifest["baseline"],
        "current": current_metrics,
        "security_facts": security_facts,
        "cases": results,
    }


def _metrics_row(label: str, metrics: Dict[str, int]) -> str:
    return (
        f"{label:<24} {metrics['cases']:>5} {metrics['expected_positives']:>5} "
        f"{metrics['expected_negatives']:>5} {metrics['tp']:>5} "
        f"{metrics['fp']:>5} {metrics['tn']:>5} {metrics['fn']:>5} "
        f"{metrics['known_gaps']:>5}"
    )


def _metrics_section(title: str, groups: Dict[str, Dict[str, int]]) -> List[str]:
    lines = [title, "Name                     Cases  Exp+  Exp-    TP    FP    TN    FN  Gaps"]
    lines.append("-" * 78)
    lines.extend(_metrics_row(name, groups[name]) for name in sorted(groups))
    return lines


def format_text_report(results: Dict[str, Any]) -> str:
    lines = [
        "=" * 78,
        f"{results['suite']} v{results['version']}",
        "=" * 78,
        "Recorded baseline:",
        "Name                     Cases  Exp+  Exp-    TP    FP    TN    FN  Gaps",
        _metrics_row("overall", results["recorded_baseline"]["overall"]),
        "",
        "Current results:",
        "Name                     Cases  Exp+  Exp-    TP    FP    TN    FN  Gaps",
        _metrics_row("overall", results["current"]["overall"]),
        "",
    ]
    lines.extend(_metrics_section("Current metrics by rule:", results["current"]["by_rule"]))
    lines.append("")
    lines.extend(
        _metrics_section(
            "Current metrics by fixture family:", results["current"]["by_family"]
        )
    )
    lines.append("")
    lines.extend(
        _metrics_section(
            "Current metrics by propagation scenario:",
            results["current"]["by_scenario"],
        )
    )

    gaps = [case for case in results["cases"] if "known_gap" in case]
    lines.extend(["", "Known gaps:"])
    for case in gaps:
        lines.append(
            f"- {case['id']}: {case['status']} "
            f"({case['known_gap']['tracking']})"
        )

    security_metrics = results["security_facts"]["metrics"]
    lines.extend(
        [
            "",
            "Security fact propagation:",
            f"- cases: {security_metrics['cases']}",
            f"- passed: {security_metrics['passed']}",
            f"- failed: {security_metrics['failed']}",
        ]
    )

    lines.append("")
    if results["success"]:
        lines.append(
            "SUCCESS: Stable expectations and security fact propagation passed; "
            "known gaps are non-blocking."
        )
    else:
        lines.append("FAILURE: " + "; ".join(results["failures"]))
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the C-GULL interprocedural regression corpus"
    )
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output")
    args = parser.parse_args()

    results = run_interprocedural_corpus(args.manifest)
    report = (
        json.dumps(results, indent=2, sort_keys=True)
        if args.format == "json"
        else format_text_report(results)
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as output_file:
            output_file.write(report)
            output_file.write("\n")
    else:
        print(report)
    raise SystemExit(0 if results["success"] else 1)


if __name__ == "__main__":
    main()
