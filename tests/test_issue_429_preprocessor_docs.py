"""Regression coverage for issue #429 symbolic-preprocessor documentation."""

from __future__ import annotations

import argparse
from pathlib import Path
import unittest

from cgull.cli import build_parser


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestIssue429SymbolicPreprocessorDocs(unittest.TestCase):
    def test_preprocessor_cli_help_matches_documented_surface(self):
        parser = build_parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        preprocessor_parser = subparsers.choices["preprocessor"]
        help_text = preprocessor_parser.format_help()

        for option in (
            "--verbose",
            "--json",
            "--config",
            "--ignore-file",
            "--ignore-pattern",
        ):
            self.assertIn(option, help_text)

    def test_symbolic_guide_covers_public_semantics_and_limits(self):
        guide = (
            REPO_ROOT / "docs" / "analysis" / "symbolic-preprocessor.md"
        ).read_text(encoding="utf-8")

        for phrase in (
            "Concrete preprocessing",
            "Symbolic preprocessor analysis",
            "cgull preprocessor src/",
            "#elifdef",
            "#elifndef",
            "opaque `Predicate` atoms",
            "context condition",
            "effective condition",
            "CGULL-054",
            "CGULL-055",
            "**Low**",
            "derive_branch_witnesses(tree)",
            "`satisfiable`",
            "`unreachable`",
            "`unsupported`",
            "`limit_exceeded`",
            "exact flag-map deduplication",
            "64 distinct Boolean atoms",
            "100,000 BDD nodes",
            "500,000 work units",
            "It is **not** proof",
            "pcpp",
        ):
            self.assertIn(phrase, guide)

    def test_public_docs_link_to_the_symbolic_contract(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        docs_index = (REPO_ROOT / "docs" / "README.md").read_text(encoding="utf-8")
        preprocessing = (REPO_ROOT / "docs" / "preprocessing.md").read_text(
            encoding="utf-8"
        )
        analysis_model = (REPO_ROOT / "docs" / "analysis-model.md").read_text(
            encoding="utf-8"
        )
        configuration = (REPO_ROOT / "docs" / "configuration.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("docs/analysis/symbolic-preprocessor.md", readme)
        self.assertIn("analysis/symbolic-preprocessor.md", docs_index)
        self.assertIn("analysis/symbolic-preprocessor.md", preprocessing)
        self.assertIn("analysis/symbolic-preprocessor.md", analysis_model)
        self.assertIn("analysis/symbolic-preprocessor.md", configuration)


if __name__ == "__main__":
    unittest.main()
