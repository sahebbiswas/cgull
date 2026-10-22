"""Issue #589: `--fail-on` must not fail on findings the engine did not fully prove.

FALLBACK-confidence findings from structural engines stay in every report, but
only count toward the exit status with `--strict-confidence`.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from cgull.cli import main
from cgull.config import load_config
from cgull.engine import CGullScanner
from cgull.gating import (
    GateCounts,
    count_for_gate,
    excluded_by_confidence,
    gate_fails,
    is_fallback_confidence,
)
from cgull.models import Confidence, Issue, ScanResult, Severity
from cgull.reporter import ReportGenerator


def _issue(impact=Severity.HIGH, confidence=Confidence.FALLBACK, engine="AST", line=1):
    return Issue(
        rule_id="CGULL-004",
        rule_name="Missing Null Check on Function Parameters",
        impact=impact,
        file_path="sample.c",
        line_number=line,
        engine=engine,
        confidence=confidence,
        fingerprint=f"fp-{impact.value}-{engine}-{confidence}-{line}",
    )


def _result(issues):
    return ScanResult(
        target_path="sample.c",
        scanned_files_count=1,
        total_lines_of_code=10,
        total_issues_count=len(issues),
        high_severity_count=sum(1 for i in issues if i.impact == Severity.HIGH),
        medium_severity_count=sum(1 for i in issues if i.impact == Severity.MEDIUM),
        low_severity_count=sum(1 for i in issues if i.impact == Severity.LOW),
        scan_duration_seconds=0.0,
        timestamp="2026-01-01T00:00:00+00:00",
        issues=list(issues),
    )


class TestGateCounting(unittest.TestCase):
    def test_info_findings_count_for_low_and_all_like_before(self):
        counts = count_for_gate([_issue(Severity.INFO, Confidence.FULL), _issue(Severity.INFO, Confidence.FALLBACK, line=2)])
        self.assertEqual((counts.info_full, counts.info_fallback), (1, 1))
        self.assertTrue(gate_fails("all", counts))
        self.assertTrue(gate_fails("low", counts))
        self.assertFalse(gate_fails("medium", counts))
        self.assertFalse(gate_fails("high", counts))
        only_fallback = count_for_gate([_issue(Severity.INFO, Confidence.FALLBACK)])
        self.assertFalse(gate_fails("all", only_fallback))
        self.assertTrue(gate_fails("all", only_fallback, strict_confidence=True))

    def test_structural_fallback_is_fallback_confidence(self):
        for engine in ("AST", "AST-CFG", "Interprocedural", "Symbolic preprocessor"):
            self.assertTrue(is_fallback_confidence(_issue(engine=engine)), engine)

    def test_regex_engine_and_other_confidences_are_not_demoted(self):
        self.assertFalse(is_fallback_confidence(_issue(engine="Regex")))
        self.assertFalse(is_fallback_confidence(_issue(engine="regex")))
        self.assertFalse(is_fallback_confidence(_issue(confidence=Confidence.FULL)))
        self.assertFalse(is_fallback_confidence(_issue(confidence=Confidence.LIMITED)))
        self.assertFalse(is_fallback_confidence(_issue(confidence=None)))

    def test_count_splits_severity_by_confidence(self):
        counts = count_for_gate(
            [
                _issue(Severity.HIGH, Confidence.FULL),
                _issue(Severity.HIGH, Confidence.FALLBACK),
                _issue(Severity.HIGH, Confidence.FALLBACK),
                _issue(Severity.MEDIUM, Confidence.FALLBACK),
                _issue(Severity.LOW, Confidence.FULL),
            ]
        )
        self.assertEqual((counts.high_full, counts.high_fallback), (1, 2))
        self.assertEqual((counts.medium_full, counts.medium_fallback), (0, 1))
        self.assertEqual((counts.low_full, counts.low_fallback), (1, 0))
        self.assertEqual(counts.high, 3)
        self.assertEqual(counts.fallback_total, 3)

    def test_gate_matrix(self):
        only_fallback_high = GateCounts(high_fallback=3)
        only_fallback_medium = GateCounts(medium_fallback=1)
        full_high = GateCounts(high_full=1, high_fallback=3)
        full_low = GateCounts(low_full=1)

        for fail_on in ("high", "medium", "low", "all"):
            self.assertFalse(gate_fails(fail_on, only_fallback_high), fail_on)
            self.assertTrue(gate_fails(fail_on, only_fallback_high, strict_confidence=True), fail_on)
            self.assertTrue(gate_fails(fail_on, full_high), fail_on)

        self.assertFalse(gate_fails("high", only_fallback_medium, strict_confidence=True))
        self.assertTrue(gate_fails("medium", only_fallback_medium, strict_confidence=True))
        self.assertFalse(gate_fails("medium", only_fallback_medium))
        self.assertFalse(gate_fails("medium", full_low))
        self.assertTrue(gate_fails("low", full_low))
        self.assertFalse(gate_fails(None, full_high))

    def test_excluded_by_confidence_follows_threshold(self):
        counts = GateCounts(high_fallback=2, medium_fallback=3, low_fallback=4)
        self.assertEqual(excluded_by_confidence("high", counts), 2)
        self.assertEqual(excluded_by_confidence("medium", counts), 5)
        self.assertEqual(excluded_by_confidence("low", counts), 9)
        self.assertEqual(excluded_by_confidence("all", counts), 9)
        self.assertEqual(excluded_by_confidence(None, counts), 0)


class TestCliGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.c_file = os.path.join(self.temp_dir, "sample.c")
        with open(self.c_file, "w", encoding="utf-8") as f:
            f.write("int main(void) { return 0; }\n")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run(self, argv, issues):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(CGullScanner, "scan_path", return_value=_result(issues)):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["scan", self.c_file, "-q", *argv])
        return code, out.getvalue(), err.getvalue()

    def _config(self, text):
        path = os.path.join(self.temp_dir, "cgull.toml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_fallback_only_high_passes_by_default(self):
        code, _, err = self._run(["--fail-on", "high"], [_issue(), _issue(line=2)])
        self.assertEqual(code, 0)
        self.assertIn("2 FALLBACK-confidence finding(s)", err)
        self.assertIn("--strict-confidence", err)

    def test_fail_on_high_alias_follows_same_policy(self):
        code, _, _ = self._run(["--fail-on-high"], [_issue()])
        self.assertEqual(code, 0)
        code, _, _ = self._run(["--fail-on-high", "--strict-confidence"], [_issue()])
        self.assertEqual(code, 1)

    def test_strict_confidence_flag_counts_fallback(self):
        code, _, err = self._run(["--fail-on", "high", "--strict-confidence"], [_issue()])
        self.assertEqual(code, 1)
        self.assertNotIn("FALLBACK-confidence finding(s)", err)

    def test_config_strict_confidence_counts_fallback(self):
        config = self._config('schema_version = 1\n\n[output]\nstrict_confidence = true\n')
        code, _, _ = self._run(["--config", config, "--fail-on", "high"], [_issue()])
        self.assertEqual(code, 1)

    def test_config_strict_confidence_defaults_to_false(self):
        config = self._config('schema_version = 1\n\n[output]\nfail_on = "high"\n')
        code, _, _ = self._run(["--config", config], [_issue()])
        self.assertEqual(code, 0)
        self.assertFalse(load_config(config_path=config, target_path=self.temp_dir).strict_confidence)

    def test_invalid_config_value_warns_and_keeps_default(self):
        config = self._config('schema_version = 1\n\n[output]\nstrict_confidence = "maybe"\n')
        loaded = load_config(config_path=config, target_path=self.temp_dir)
        self.assertFalse(loaded.strict_confidence)
        self.assertTrue(any("strict_confidence" in w for w in loaded.warnings))

    def test_full_confidence_high_still_fails_with_fallback_present(self):
        issues = [_issue(), _issue(confidence=Confidence.FULL, line=2)]
        code, _, err = self._run(["--fail-on", "high"], issues)
        self.assertEqual(code, 1)
        self.assertIn("1 FALLBACK-confidence finding(s)", err)

    def test_regex_engine_fallback_confidence_still_fails(self):
        code, _, _ = self._run(["--fail-on", "high"], [_issue(engine="Regex")])
        self.assertEqual(code, 1)

    def test_unproven_medium_does_not_fail_medium_gate_by_default(self):
        issues = [_issue(Severity.MEDIUM)]
        self.assertEqual(self._run(["--fail-on", "medium"], issues)[0], 0)
        self.assertEqual(self._run(["--fail-on", "medium", "--strict-confidence"], issues)[0], 1)

    def test_no_note_without_fail_on(self):
        code, _, err = self._run([], [_issue()])
        self.assertEqual(code, 0)
        self.assertNotIn("FALLBACK-confidence", err)

    def test_reports_keep_fallback_findings_with_impact_and_confidence(self):
        result = _result([_issue(), _issue(confidence=Confidence.FULL, line=2)])
        payload = json.loads(ReportGenerator.to_json(result))
        rows = payload["issues"]
        self.assertEqual({row["impact"] for row in rows}, {"High"})
        self.assertEqual({row["confidence"] for row in rows}, {"FALLBACK", "FULL"})
        sarif = json.loads(ReportGenerator.to_sarif(result))
        confidences = {
            r["properties"]["confidence"] for r in sarif["runs"][0]["results"] if "confidence" in r.get("properties", {})
        }
        self.assertEqual(confidences, {"FALLBACK", "FULL"})

    def test_terminal_and_markdown_summaries_split_high_by_confidence(self):
        result = _result([_issue(), _issue(line=2), _issue(confidence=Confidence.FULL, line=3)])
        text = ReportGenerator.to_terminal_text(result)
        self.assertIn("1 counted, 2 structural FALLBACK", text)
        markdown = ReportGenerator.to_markdown(result)
        self.assertIn("| High: counted by default | 1 |", markdown)
        self.assertIn("| High: structural `FALLBACK` | 2 |", markdown)

    def test_terminal_summary_omits_split_without_high_findings(self):
        text = ReportGenerator.to_terminal_text(_result([_issue(Severity.LOW)]))
        self.assertNotIn("High by confidence", text)


if __name__ == "__main__":
    unittest.main()
