"""Tests for the focused interprocedural regression corpus."""

import json
import os
from types import SimpleNamespace
from unittest.mock import patch

from benchmarks.run_interprocedural import (
    DEFAULT_MANIFEST,
    format_text_report,
    run_interprocedural_corpus,
)


def _load_manifest():
    with open(DEFAULT_MANIFEST, "r", encoding="utf-8") as manifest_file:
        return json.load(manifest_file)


def _mock_scan_path(manifest, overrides=None):
    overrides = overrides or {}
    cases_by_file = {
        os.path.basename(case["file"]): case for case in manifest["cases"]
    }

    def scan_path(_scanner, file_path):
        case = cases_by_file[os.path.basename(file_path)]
        detected = overrides.get(case["id"], case["baseline_detected"])
        issues = [SimpleNamespace(rule_id=case["rule_id"])] if detected else []
        return SimpleNamespace(
            issues=issues,
            failed_paths=[],
            files_failed=0,
            scan_errors=[],
            get_overall_analysis_status=lambda: "success",
        )

    return scan_path


def test_manifest_covers_required_scenarios_families_and_juliet_variants():
    manifest = _load_manifest()
    cases = manifest["cases"]
    assert len(cases) == 22
    assert len({case["id"] for case in cases}) == len(cases)
    fixture_dir = os.path.join(os.path.dirname(DEFAULT_MANIFEST), "fixtures")
    fixture_sources = {
        os.path.join("fixtures", filename)
        for filename in os.listdir(fixture_dir)
        if filename.endswith(".c")
    }
    assert {case["file"] for case in cases} == fixture_sources

    for scenario in manifest["required_scenarios"]:
        labels = {
            case["vulnerable"] for case in cases if case["scenario"] == scenario
        }
        assert labels == {False, True}

    for family in manifest["required_families"]:
        labels = {
            case["vulnerable"] for case in cases if case["family"] == family
        }
        assert labels == {False, True}

    juliet_variants = {
        (case["rule_id"], case["variant"])
        for case in cases
        if case["scenario"] == "juliet_variants"
    }
    assert juliet_variants == {
        ("CGULL-002", "GoodSource/BadSink"),
        ("CGULL-002", "BadSource/GoodSink"),
        ("CGULL-030", "GoodSource/BadSink"),
        ("CGULL-030", "BadSource/GoodSink"),
    }

    manifest_dir = os.path.dirname(DEFAULT_MANIFEST)
    for case in cases:
        is_gap = case["baseline_detected"] != case["vulnerable"]
        assert ("known_gap" in case) is is_gap
        if is_gap:
            tracking_path = case["known_gap"]["tracking"].split("#", 1)[0]
            assert os.path.isfile(os.path.join(manifest_dir, tracking_path))


def test_current_corpus_accepts_stable_expectations_and_known_gaps():
    results = run_interprocedural_corpus()
    assert results["success"] is True
    assert results["recorded_baseline"]["overall"] == {
        "cases": 22,
        "expected_positives": 9,
        "expected_negatives": 13,
        "tp": 6,
        "fp": 7,
        "tn": 6,
        "fn": 3,
        "known_gaps": 10,
    }
    for case in results["cases"]:
        expected_statuses = (
            {"known_gap", "resolved_known_gap"}
            if "known_gap" in case
            else {"pass"}
        )
        assert case["status"] in expected_statuses

    repeated_results = run_interprocedural_corpus()
    assert repeated_results["current"] == results["current"]
    assert format_text_report(repeated_results) == format_text_report(results)


def test_resolving_known_gap_is_non_blocking():
    manifest = _load_manifest()
    mocked_scan = _mock_scan_path(manifest, {"direct_wrapper_safe": False})
    with patch(
        "benchmarks.run_interprocedural.CGullScanner.scan_path", new=mocked_scan
    ):
        results = run_interprocedural_corpus()

    resolved = next(
        case for case in results["cases"] if case["id"] == "direct_wrapper_safe"
    )
    assert results["success"] is True
    assert resolved["status"] == "resolved_known_gap"
    assert results["current"]["overall"]["fp"] == 6
    assert results["current"]["overall"]["tn"] == 7


def test_non_gap_regression_is_blocking():
    manifest = _load_manifest()
    mocked_scan = _mock_scan_path(manifest, {"direct_wrapper_unsafe": False})
    with patch(
        "benchmarks.run_interprocedural.CGullScanner.scan_path", new=mocked_scan
    ):
        results = run_interprocedural_corpus()

    assert results["success"] is False
    assert results["failures"] == [
        "direct_wrapper_unsafe: expected detected=True, got detected=False"
    ]
