"""Regression coverage for issue #455 project-state logging and retention."""

from __future__ import annotations

import io
import json
import logging
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cgull.cli import main
from cgull.config import load_config
from cgull.logging_config import (
    JSONLFormatter,
    _prune_default_capture_logs,
    configure_logging,
)
from cgull.project_state import (
    DEFAULT_LOG_RETENTION_RUNS,
    effective_target_root,
    read_logging_retention,
    resolve_project_state_root,
)


@contextmanager
def clean_logging_handlers():
    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_level = root.level
    try:
        yield
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()
        root.setLevel(previous_level)
        for handler in previous_handlers:
            root.addHandler(handler)


def _capture_files(root: Path):
    log_dir = root / ".cgull" / "logs"
    if not log_dir.is_dir():
        return []
    return sorted(path for path in log_dir.glob("scan-*.log") if path.is_file())


def _owned_name(instant: datetime, pid: int = 1) -> str:
    stamp = instant.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"scan-{stamp}-{pid}.log"


class TestProjectStateRoot(unittest.TestCase):
    def test_explicit_existing_config_establishes_state_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            project = base / "project"
            elsewhere = base / "elsewhere"
            project.mkdir()
            elsewhere.mkdir()
            config = project / ".cgull.toml"
            config.write_text("schema_version = 1\n", encoding="utf-8")

            self.assertEqual(
                resolve_project_state_root([elsewhere], str(config)),
                str(project.resolve()),
            )

    def test_discovered_config_beats_nested_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            nested = project / "src" / "nested"
            nested.mkdir(parents=True)
            (project / ".cgull.toml").write_text(
                "schema_version = 1\n", encoding="utf-8"
            )

            self.assertEqual(
                resolve_project_state_root([nested]),
                str(project.resolve()),
            )

    def test_no_config_directory_and_single_file_use_target_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            source = project / "sample.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

            self.assertEqual(resolve_project_state_root([project]), str(project.resolve()))
            self.assertEqual(resolve_project_state_root([source]), str(project.resolve()))

    def test_multiple_targets_use_common_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            left = project / "left"
            right = project / "right"
            left.mkdir()
            right.mkdir()

            self.assertEqual(
                effective_target_root([left, right]),
                str(project.resolve()),
            )

    def test_cross_drive_commonpath_failure_falls_back_to_cwd(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cgull.project_state.os.path.commonpath", side_effect=ValueError):
                with patch("cgull.project_state.os.getcwd", return_value=tmpdir):
                    self.assertEqual(effective_target_root(["a", "b"]), tmpdir)


class TestLoggingRetentionConfig(unittest.TestCase):
    def test_retention_is_parsed_by_full_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".cgull.toml"
            config_path.write_text(
                "schema_version = 1\n[logging]\nretention_runs = 7\n",
                encoding="utf-8",
            )
            config = load_config(config_path=str(config_path))
            self.assertEqual(config.logging_retention_runs, 7)
            self.assertFalse(any("retention_runs" in warning for warning in config.warnings))

    def test_invalid_retention_warns_and_uses_default(self):
        invalid_values = ("-1", "0", '"many"', "true")
        for value in invalid_values:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmpdir:
                config_path = Path(tmpdir) / ".cgull.toml"
                config_path.write_text(
                    f"schema_version = 1\n[logging]\nretention_runs = {value}\n",
                    encoding="utf-8",
                )
                config = load_config(config_path=str(config_path))
                self.assertEqual(
                    config.logging_retention_runs,
                    DEFAULT_LOG_RETENTION_RUNS,
                )
                self.assertTrue(
                    any("[logging].retention_runs" in warning for warning in config.warnings)
                )
                self.assertEqual(
                    read_logging_retention([tmpdir], str(config_path)),
                    DEFAULT_LOG_RETENTION_RUNS,
                )

    def test_lightweight_bootstrap_reads_valid_retention(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".cgull.toml"
            config_path.write_text(
                "[logging]\nretention_runs = 3\n", encoding="utf-8"
            )
            self.assertEqual(read_logging_retention([tmpdir], str(config_path)), 3)


class TestCapturePlacementAndPruning(unittest.TestCase):
    def test_default_capture_lands_under_project_state_root(self):
        with tempfile.TemporaryDirectory() as tmpdir, clean_logging_handlers():
            project = Path(tmpdir)
            configure_logging(project_state_root=str(project))
            logger = logging.getLogger("cgull.issue455")
            logger.info("captured")
            for handler in logging.getLogger().handlers:
                handler.flush()

            captures = _capture_files(project)
            self.assertEqual(len(captures), 1)
            record = json.loads(captures[0].read_text(encoding="utf-8").strip())
            self.assertEqual(record["message"], "captured")

    def test_two_default_captures_never_append_same_file(self):
        with tempfile.TemporaryDirectory() as tmpdir, clean_logging_handlers():
            project = Path(tmpdir)
            configure_logging(project_state_root=str(project))
            first = _capture_files(project)
            self.assertEqual(len(first), 1)
            configure_logging(project_state_root=str(project))
            second = _capture_files(project)
            self.assertEqual(len(second), 2)
            self.assertNotEqual(first[0].name, second[-1].name)

    def test_twenty_first_run_leaves_newest_twenty_owned_captures(self):
        with tempfile.TemporaryDirectory() as tmpdir, clean_logging_handlers():
            project = Path(tmpdir)
            log_dir = project / ".cgull" / "logs"
            log_dir.mkdir(parents=True)
            start = datetime(2026, 9, 1, tzinfo=timezone.utc)
            old_names = []
            for index in range(20):
                path = log_dir / _owned_name(start + timedelta(seconds=index), index + 1)
                path.write_text("{}\n", encoding="utf-8")
                old_names.append(path.name)

            configure_logging(project_state_root=str(project), retention_runs=20)
            captures = _capture_files(project)
            self.assertEqual(len(captures), 20)
            self.assertFalse((log_dir / old_names[0]).exists())
            self.assertTrue((log_dir / old_names[-1]).exists())

    def test_pruning_ignores_unrelated_and_legacy_text_logs(self):
        with tempfile.TemporaryDirectory() as tmpdir, clean_logging_handlers():
            project = Path(tmpdir)
            log_dir = project / ".cgull" / "logs"
            log_dir.mkdir(parents=True)
            start = datetime(2026, 9, 1, tzinfo=timezone.utc)
            for index in range(3):
                (log_dir / _owned_name(start + timedelta(seconds=index), index + 1)).write_text(
                    "{}\n", encoding="utf-8"
                )
            unrelated = log_dir / "application.log"
            unrelated.write_text("keep\n", encoding="utf-8")
            unknown = log_dir / "scan-not-owned.log"
            unknown.write_text("keep\n", encoding="utf-8")
            directory = log_dir / "scan-20260901T000000.000000Z-99.log"
            directory.mkdir()
            legacy = log_dir / "legacy-text.log"

            configure_logging(
                project_state_root=str(project),
                retention_runs=2,
                log_file=str(legacy),
            )

            self.assertTrue(unrelated.exists())
            self.assertTrue(unknown.exists())
            self.assertTrue(directory.is_dir())
            self.assertTrue(legacy.exists())
            self.assertEqual(len(_capture_files(project)), 2)

    def test_prune_failure_warns_once_and_capture_still_opens(self):
        with tempfile.TemporaryDirectory() as tmpdir, clean_logging_handlers():
            stderr = io.StringIO()
            with patch("sys.stderr", stderr), patch(
                "cgull.logging_config._prune_default_capture_logs",
                side_effect=OSError("cannot prune"),
            ):
                configure_logging(project_state_root=tmpdir)
                logging.getLogger("cgull.issue455").warning("scan continues")
                for handler in logging.getLogger().handlers:
                    handler.flush()

            self.assertEqual(stderr.getvalue().count("Unable to prune diagnostic capture"), 1)
            self.assertIn("scan continues", stderr.getvalue())
            captures = _capture_files(Path(tmpdir))
            self.assertEqual(len(captures), 1)
            self.assertTrue(
                any(
                    isinstance(handler.formatter, JSONLFormatter)
                    for handler in logging.getLogger().handlers
                )
            )

    def test_prune_helper_deletes_only_owned_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            start = datetime(2026, 9, 1, tzinfo=timezone.utc)
            for index in range(4):
                (log_dir / _owned_name(start + timedelta(seconds=index), index + 1)).write_text(
                    "{}\n", encoding="utf-8"
                )
            unrelated = log_dir / "other.log"
            unrelated.write_text("keep\n", encoding="utf-8")

            _prune_default_capture_logs(log_dir, 3)
            self.assertEqual(
                len([path for path in log_dir.glob("scan-*.log") if path.is_file()]),
                2,
            )
            self.assertTrue(unrelated.exists())

    def test_cli_bootstrap_uses_discovered_project_root(self):
        with tempfile.TemporaryDirectory() as tmpdir, clean_logging_handlers():
            project = Path(tmpdir)
            nested = project / "src"
            nested.mkdir()
            source = nested / "sample.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (project / ".cgull.toml").write_text(
                "schema_version = 1\n[logging]\nretention_runs = 20\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                rc = main(["scan", str(source), "--quiet"])

            self.assertEqual(rc, 0)
            self.assertEqual(len(_capture_files(project)), 1)
            self.assertFalse((nested / ".cgull" / "logs").exists())


if __name__ == "__main__":
    unittest.main()
