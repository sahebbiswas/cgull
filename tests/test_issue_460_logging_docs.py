"""Regression coverage for issue #460 logging documentation contracts."""

from __future__ import annotations

import argparse
import io
from pathlib import Path
import tempfile
import unittest

from cgull.cli import build_parser
from cgull.config import load_config
from cgull.project_init import initialize_project
from cgull.project_state import DEFAULT_LOG_RETENTION_RUNS


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestIssue460LoggingDocs(unittest.TestCase):
    def test_cli_help_documents_effective_logging_thresholds(self):
        parser = build_parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        scan_parser = subparsers.choices["scan"]

        for help_text in (parser.format_help(), scan_parser.format_help()):
            normalized = " ".join(help_text.split())
            self.assertIn(
                "default WARNING; -v INFO; -vv DEBUG; -vvv TRACE",
                normalized,
            )
            self.assertIn("overrides -v/-vv/-vvv", normalized)
            self.assertIn("automatic project-local JSONL diagnostic capture", normalized)
            self.assertIn("additive human-readable diagnostic log", normalized)

    def test_init_advertises_logging_retention_and_generated_toml_parses(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stderr = io.StringIO()
            rc = initialize_project(
                root,
                profile="comprehensive",
                stdout=io.StringIO(),
                stderr=stderr,
            )

            self.assertEqual(rc, 0, stderr.getvalue())
            config_path = root / ".cgull.toml"
            content = config_path.read_text(encoding="utf-8")
            self.assertIn("[logging]", content)
            self.assertIn(
                f"retention_runs = {DEFAULT_LOG_RETENTION_RUNS}",
                content,
            )

            config = load_config(config_path=str(config_path), target_path=str(root))
            self.assertIsNone(config.error)
            self.assertEqual(
                config.logging_retention_runs,
                DEFAULT_LOG_RETENTION_RUNS,
            )

    def test_logging_guide_and_cross_links_cover_public_contract(self):
        logging_doc = (REPO_ROOT / "docs" / "logging.md").read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        docs_index = (REPO_ROOT / "docs" / "README.md").read_text(encoding="utf-8")
        telemetry = (REPO_ROOT / "docs" / "scan-telemetry.md").read_text(encoding="utf-8")
        reporting = (REPO_ROOT / "docs" / "reporting-and-ci.md").read_text(encoding="utf-8")

        self.assertIn("docs/logging.md", readme)
        self.assertIn("logging.md", docs_index)
        self.assertIn("logging.md", telemetry)
        self.assertIn("logging.md", reporting)

        for phrase in (
            "INFO, DEBUG, and TRACE records are **not** retained secretly",
            "[logging].retention_runs",
            "retention_runs = 20",
            "--quiet",
            "does not upload",
            "does not claim automatic secret or PII redaction",
            "--log-file PATH",
            "unavailable after the fact",
        ):
            self.assertIn(phrase, logging_doc)

    def test_release_notes_record_logging_behavior_and_benchmark(self):
        notes = (REPO_ROOT / "docs" / "release-notes-0.11.27.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("WARNING", notes)
        self.assertIn("--no-log", notes)
        self.assertIn("retention_runs", notes)
        self.assertIn("coordinator", notes)
        self.assertIn("-0.38%", notes)
        self.assertIn("+91.75%", notes)


if __name__ == "__main__":
    unittest.main()
