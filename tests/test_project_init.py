"""Tests for the unified ``cgull init`` project setup workflow."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path

from cgull.cli import build_parser, main
from cgull.config import load_config
from cgull.project_init import initialize_project


class TTYStringIO(io.StringIO):
    def isatty(self) -> bool:
        return True


class TestProjectInit(unittest.TestCase):
    def test_noninteractive_defaults_to_focused_and_detects_existing_include_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "include").mkdir()
            stdout = io.StringIO()
            stderr = io.StringIO()

            rc = initialize_project(root, stdout=stdout, stderr=stderr)

            self.assertEqual(rc, 0, stderr.getvalue())
            config_path = root / ".cgull.toml"
            self.assertTrue(config_path.is_file())
            cfg = load_config(config_path=str(config_path), target_path=str(root))
            self.assertIsNone(cfg.error)
            self.assertEqual(set(cfg.skipped_rules), {"CGULL-019", "CGULL-025"})
            self.assertEqual(cfg.mode, None)
            self.assertEqual(cfg.include_roots, [os.path.realpath(root / "include")])
            self.assertIn("Finding profile: focused", stdout.getvalue())

    def test_comprehensive_profile_has_no_active_skip_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rc = initialize_project(root, profile="comprehensive", stdout=io.StringIO(), stderr=io.StringIO())
            self.assertEqual(rc, 0)
            content = (root / ".cgull.toml").read_text(encoding="utf-8")
            cfg = load_config(config_path=str(root / ".cgull.toml"), target_path=str(root))
            self.assertEqual(cfg.skipped_rules, {})
            self.assertNotIn("skip = {", content)

    def test_existing_cgull_config_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            existing = root / ".cgull.toml"
            existing.write_text("schema_version = 1\n", encoding="utf-8")
            stderr = io.StringIO()
            rc = initialize_project(root, stdout=io.StringIO(), stderr=stderr)
            self.assertEqual(rc, 2)
            self.assertEqual(existing.read_text(encoding="utf-8"), "schema_version = 1\n")
            self.assertIn("Not overwriting or shadowing", stderr.getvalue())

    def test_pyproject_tool_cgull_prevents_shadowing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[tool.cgull]\nschema_version = 1\n", encoding="utf-8")
            rc = initialize_project(root, stdout=io.StringIO(), stderr=io.StringIO())
            self.assertEqual(rc, 2)
            self.assertFalse((root / ".cgull.toml").exists())

    def test_migrate_preserves_negation_order_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".cgullignore").write_text(
                "build/\n!build/keep.c\n./generated/\nbuild/\n",
                encoding="utf-8",
            )
            (root / ".cgullincludes").write_text("./include\ninc\\platform\ninclude\n", encoding="utf-8")
            (root / "include").mkdir()
            stdout = io.StringIO()

            rc = initialize_project(root, migrate=True, stdout=stdout, stderr=io.StringIO())

            self.assertEqual(rc, 0)
            content = (root / ".cgull.toml").read_text(encoding="utf-8")
            self.assertLess(content.index('"build/"'), content.index('"!build/keep.c"'))
            self.assertLess(content.index('"!build/keep.c"'), content.index('"generated/"'))
            self.assertEqual(content.count('"build/"'), 1)
            self.assertEqual(content.count('"include"'), 1)
            self.assertIn('"inc/platform"', content)
            self.assertTrue((root / ".cgullignore").exists())
            self.assertTrue((root / ".cgullincludes").exists())
            self.assertIn("not modified", stdout.getvalue())

    def test_interactive_custom_lists_metadata_and_writes_only_selected_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdin = TTYStringIO("3\nCGULL-001, CGULL-019\n")
            stdout = TTYStringIO()
            stderr = io.StringIO()

            rc = initialize_project(root, stdin=stdin, stdout=stdout, stderr=stderr)

            self.assertEqual(rc, 0, stderr.getvalue())
            cfg = load_config(config_path=str(root / ".cgull.toml"), target_path=str(root))
            self.assertEqual(set(cfg.skipped_rules), {"CGULL-001", "CGULL-019"})
            output = stdout.getvalue()
            self.assertIn("ID | name | category | severity", output)
            self.assertIn("CGULL-001", output)

    def test_interactive_enter_selects_focused_and_confirms_detected_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "include").mkdir(parents=True)
            stdin = TTYStringIO("\n\n")
            stdout = TTYStringIO()
            rc = initialize_project(root, stdin=stdin, stdout=stdout, stderr=io.StringIO())
            self.assertEqual(rc, 0)
            content = (root / ".cgull.toml").read_text(encoding="utf-8")
            self.assertIn('"src/include"', content)
            self.assertIn("Finding profile: focused", stdout.getvalue())

    def test_compile_commands_is_reported_but_not_copied_into_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            stdout = io.StringIO()
            rc = initialize_project(root, stdout=stdout, stderr=io.StringIO())
            self.assertEqual(rc, 0)
            content = (root / ".cgull.toml").read_text(encoding="utf-8")
            self.assertNotIn("compile_commands", content)
            self.assertIn("auto-discover", stdout.getvalue())

    def test_public_parser_advertises_init_not_init_ignore(self):
        parser = build_parser()
        help_text = parser.format_help()
        self.assertIn("init", help_text)
        self.assertNotIn("init-ignore", help_text)
        args = parser.parse_args(["init", "some-project", "--profile", "focused"])
        self.assertEqual(args.command, "init")
        self.assertEqual(args.path, "some-project")
        self.assertEqual(args.profile, "focused")

    def test_removed_init_ignore_returns_migration_hint(self):
        stderr = io.StringIO()
        original = os.sys.stderr
        try:
            os.sys.stderr = stderr
            rc = main(["init-ignore"])
        finally:
            os.sys.stderr = original
        self.assertEqual(rc, 2)
        self.assertIn("cgull init", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
