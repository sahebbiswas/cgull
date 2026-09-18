"""Regression coverage for issue #429 symbolic-preprocessor documentation."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit

from cgull.cli import build_parser


REPO_ROOT = Path(__file__).resolve().parents[1]
_MARKDOWN_LINK = re.compile(r"\\[[^\\]]+\\]\\(([^)]+)\\)")
_GITHUB_BLOB_PREFIX = "/sahebbiswas/cgull/blob/main/"


def _repository_link_targets(document: Path) -> set[Path]:
    """Resolve repository-local Markdown link targets from one document."""

    targets: set[Path] = set()
    for match in _MARKDOWN_LINK.finditer(document.read_text(encoding="utf-8")):
        raw_target = match.group(1).strip().strip("<>")
        # A Markdown title, when present, follows the URL after whitespace.
        target = raw_target.split(maxsplit=1)[0]
        parsed = urlsplit(target)

        if parsed.scheme:
            if parsed.scheme not in ("http", "https") or parsed.netloc != "github.com":
                continue
            if not parsed.path.startswith(_GITHUB_BLOB_PREFIX):
                continue
            relative = unquote(parsed.path[len(_GITHUB_BLOB_PREFIX):])
            targets.add((REPO_ROOT / relative).resolve())
            continue

        if target.startswith("#") or not parsed.path:
            continue
        targets.add((document.parent / unquote(parsed.path)).resolve())

    return targets


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
        documents = (
            REPO_ROOT / "README.md",
            REPO_ROOT / "docs" / "README.md",
            REPO_ROOT / "docs" / "preprocessing.md",
            REPO_ROOT / "docs" / "analysis-model.md",
            REPO_ROOT / "docs" / "configuration.md",
        )
        symbolic_guide = (
            REPO_ROOT / "docs" / "analysis" / "symbolic-preprocessor.md"
        ).resolve()

        for document in documents:
            targets = _repository_link_targets(document)
            self.assertIn(
                symbolic_guide,
                targets,
                f"{document.relative_to(REPO_ROOT)} must link to the symbolic guide",
            )
            for target in targets:
                self.assertTrue(
                    target.exists(),
                    f"{document.relative_to(REPO_ROOT)} links to missing "
                    f"repository target {target}",
                )


if __name__ == "__main__":
    unittest.main()
