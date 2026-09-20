"""Tests for focused finding profiles and security-vs-policy classification."""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cgull.cli import build_parser, main
from cgull.config import load_config
from cgull.finding_profiles import (
    FOCUSED_SKIPS,
    apply_focused_skips,
    classify_issue_bucket,
    count_security_vs_policy,
    is_policy_quality_rule,
    validate_focused_profile,
)
from cgull.models import FixType, Issue, Severity
from cgull.project_init import initialize_project
from cgull.reporter import ReportGenerator
from cgull.models import ScanResult


def _issue(rule_id: str, name: str = "Example", impact: Severity = Severity.LOW) -> Issue:
    return Issue(
        rule_id=rule_id,
        rule_name=name,
        impact=impact,
        file_path="sample.c",
        line_number=1,
        column_number=1,
        code_snippet="goto cleanup;",
        message="example",
        remediation="n/a",
        cwe_id="CWE-398",
        engine="regex",
        fix_type=FixType.MANUAL_REVIEW,
    )


class TestFocusedProfile(unittest.TestCase):
    def test_focused_skips_include_goto_and_stay_low_severity(self):
        validate_focused_profile()
        self.assertEqual(set(FOCUSED_SKIPS), {"CGULL-018", "CGULL-019", "CGULL-025"})

    def test_apply_focused_skips_preserves_existing_reasons(self):
        merged = apply_focused_skips({"CGULL-018": "project keeps goto rationale"})
        self.assertEqual(merged["CGULL-018"], "project keeps goto rationale")
        self.assertIn("CGULL-019", merged)
        self.assertIn("CGULL-025", merged)

    def test_init_focused_writes_cgull_018(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rc = initialize_project(root, profile="focused", stdout=io.StringIO(), stderr=io.StringIO())
            self.assertEqual(rc, 0)
            cfg = load_config(config_path=str(root / ".cgull.toml"), target_path=str(root))
            self.assertEqual(set(cfg.skipped_rules), {"CGULL-018", "CGULL-019", "CGULL-025"})


class TestPolicyClassification(unittest.TestCase):
    def test_style_and_goto_are_policy(self):
        self.assertTrue(is_policy_quality_rule("CGULL-018"))
        self.assertTrue(is_policy_quality_rule("CGULL-025"))
        self.assertTrue(is_policy_quality_rule("CGULL-019"))
        self.assertFalse(is_policy_quality_rule("CGULL-001"))
        self.assertFalse(is_policy_quality_rule("CGULL-048"))

    def test_count_and_labels(self):
        issues = [
            _issue("CGULL-001", "Banned", Severity.HIGH),
            _issue("CGULL-018", "Goto", Severity.LOW),
            _issue("CGULL-025", "Assert", Severity.LOW),
        ]
        security, policy = count_security_vs_policy(issues)
        self.assertEqual(security, 1)
        self.assertEqual(policy, 2)
        self.assertEqual(classify_issue_bucket(issues[0]), "security")
        self.assertEqual(classify_issue_bucket(issues[1]), "policy")


class TestReportLabels(unittest.TestCase):
    def test_terminal_summary_splits_security_and_policy(self):
        result = ScanResult(
            target_path=".",
            scanned_files_count=1,
            total_lines_of_code=10,
            total_issues_count=2,
            high_severity_count=1,
            medium_severity_count=0,
            low_severity_count=1,
            scan_duration_seconds=0.01,
            timestamp="2026-01-01T00:00:00Z",
            issues=[
                _issue("CGULL-001", "Banned", Severity.HIGH),
                _issue("CGULL-018", "Goto", Severity.LOW),
            ],
        )
        text = ReportGenerator.to_terminal_text(result)
        self.assertIn("Finding classes  : security actionable 1, policy/quality 1", text)
        self.assertIn("[security]", text)
        self.assertIn("[policy]", text)
        self.assertIn("Security actionable: 1", text)
        self.assertIn("Policy / quality:    1", text)

        md = ReportGenerator.to_markdown(result)
        self.assertIn("Security actionable | 1", md)
        self.assertIn("Policy / quality | 1", md)
        self.assertIn("[security actionable]", md)
        self.assertIn("[policy/quality]", md)


class TestScanProfileFlag(unittest.TestCase):
    def test_parser_accepts_scan_profile(self):
        parser = build_parser()
        args = parser.parse_args(["scan", ".", "--profile", "focused"])
        self.assertEqual(args.profile, "focused")

    def test_scan_profile_focused_skips_goto_without_config(self):
        source = "\n".join(
            [
                "void cleanup(void);",
                "void f(int err) {",
                "    if (err) goto cleanup;",
                "    return;",
                "cleanup:",
                "    cleanup();",
                "}",
                "",
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "goto_sample.c"
            sample.write_text(source, encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                rc = main(["scan", str(sample), "--profile", "focused", "--engine", "regex", "-q"])
            self.assertEqual(rc, 0, stderr.getvalue())
            out = stdout.getvalue()
            self.assertNotIn("CGULL-018", out)
            # Focused skips goto; other policy/style rules (e.g. CGULL-013 braces) may remain.
            self.assertIn("Security actionable:", out)
            self.assertIn("Policy / quality:", out)


if __name__ == "__main__":
    unittest.main()
