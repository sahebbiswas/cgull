"""Regression coverage for issue #470 logging verbosity policy."""

import io
import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cgull.logging_config import (
    JSONLFormatter,
    TRACE_LEVEL_NUM,
    configure_logging,
    resolve_effective_log_level,
)


class TestIssue470LoggingVerbosity(unittest.TestCase):
    def setUp(self):
        self.root_logger = logging.getLogger()
        self.original_handlers = list(self.root_logger.handlers)
        self.original_level = self.root_logger.level

    def tearDown(self):
        for handler in list(self.root_logger.handlers):
            self.root_logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass
        self.root_logger.setLevel(self.original_level)
        for handler in self.original_handlers:
            if not isinstance(handler, logging.FileHandler):
                self.root_logger.addHandler(handler)

    def _emit_all_levels(self):
        logger = logging.getLogger("cgull.issue470")
        logger.setLevel(logging.NOTSET)
        logger.log(TRACE_LEVEL_NUM, "trace")
        logger.debug("debug")
        logger.info("info")
        logger.warning("warning")
        logger.error("error")
        for handler in self.root_logger.handlers:
            handler.flush()

    @staticmethod
    def _capture_records(project: Path):
        captures = list((project / ".cgull" / "logs").glob("scan-*.log"))
        if len(captures) != 1:
            raise AssertionError(f"expected one automatic capture, got {captures!r}")
        with captures[0].open(encoding="utf-8") as stream:
            return [json.loads(line) for line in stream]

    def test_effective_level_resolution_and_precedence(self):
        self.assertEqual(resolve_effective_log_level(0, None), logging.WARNING)
        self.assertEqual(resolve_effective_log_level(1, None), logging.INFO)
        self.assertEqual(resolve_effective_log_level(2, None), logging.DEBUG)
        self.assertEqual(resolve_effective_log_level(3, None), TRACE_LEVEL_NUM)
        self.assertEqual(resolve_effective_log_level(99, None), TRACE_LEVEL_NUM)
        self.assertEqual(resolve_effective_log_level(3, "error"), logging.ERROR)

    def test_automatic_capture_and_stderr_share_selected_threshold(self):
        cases = (
            (0, None, ["WARNING", "ERROR"]),
            (1, None, ["INFO", "WARNING", "ERROR"]),
            (2, None, ["DEBUG", "INFO", "WARNING", "ERROR"]),
            (3, None, ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"]),
            (3, "error", ["ERROR"]),
        )

        for verbose_count, log_level, expected_levels in cases:
            with self.subTest(verbose_count=verbose_count, log_level=log_level):
                with tempfile.TemporaryDirectory() as temp_dir:
                    project = Path(temp_dir)
                    stderr = io.StringIO()
                    with patch("sys.stderr", stderr):
                        configure_logging(
                            verbose_count=verbose_count,
                            log_level_str=log_level,
                            project_state_root=str(project),
                        )
                        self.assertEqual(
                            self.root_logger.level,
                            resolve_effective_log_level(verbose_count, log_level),
                        )
                        self._emit_all_levels()

                    records = self._capture_records(project)
                    self.assertEqual(
                        [record["level"] for record in records],
                        expected_levels,
                    )
                    self.assertEqual(
                        [
                            handler.level
                            for handler in self.root_logger.handlers
                            if isinstance(handler.formatter, JSONLFormatter)
                        ],
                        [resolve_effective_log_level(verbose_count, log_level)],
                    )
                    stderr_text = stderr.getvalue()
                    for level in ("trace", "debug", "info", "warning", "error"):
                        should_appear = level.upper() in expected_levels
                        self.assertEqual(level in stderr_text, should_appear)

    def test_explicit_text_log_uses_same_effective_threshold(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir)
            text_log = project / "diagnostics.log"
            stderr = io.StringIO()
            with patch("sys.stderr", stderr):
                configure_logging(
                    verbose_count=2,
                    log_file=str(text_log),
                    project_state_root=str(project),
                )
                self._emit_all_levels()

            content = text_log.read_text(encoding="utf-8")
            self.assertNotIn("trace", content)
            self.assertIn("debug", content)
            self.assertIn("info", content)
            self.assertIn("warning", content)
            self.assertIn("error", content)
            self.assertEqual(
                [record["level"] for record in self._capture_records(project)],
                ["DEBUG", "INFO", "WARNING", "ERROR"],
            )

    def test_explicit_log_level_can_be_less_verbose_than_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir)
            text_log = project / "errors.log"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                configure_logging(
                    verbose_count=3,
                    log_level_str="error",
                    log_file=str(text_log),
                    project_state_root=str(project),
                )
                logger = logging.getLogger("cgull.issue470.short_circuit")
                logger.setLevel(logging.NOTSET)
                self.assertFalse(logger.isEnabledFor(logging.WARNING))
                self.assertTrue(logger.isEnabledFor(logging.ERROR))
                self._emit_all_levels()

            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("warning", stderr.getvalue())
            self.assertIn("error", stderr.getvalue())
            self.assertNotIn("warning", text_log.read_text(encoding="utf-8"))
            self.assertEqual(
                [record["level"] for record in self._capture_records(project)],
                ["ERROR"],
            )


if __name__ == "__main__":
    unittest.main()
