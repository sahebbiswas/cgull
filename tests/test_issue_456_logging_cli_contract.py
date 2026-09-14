"""Regression coverage for issue #456 logging CLI compatibility."""

import io
import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cgull.cli import _command_after_global_options, build_parser, main
from cgull.logging_config import TRACE_LEVEL_NUM, configure_logging


class TestIssue456LoggingCliContract(unittest.TestCase):
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

    def _emit_levels(self):
        logger = logging.getLogger("cgull.issue456")
        logger.setLevel(logging.NOTSET)
        logger.log(TRACE_LEVEL_NUM, "trace-message")
        logger.debug("debug-message")
        logger.info("info-message")
        logger.warning("warning-message")
        logger.error("error-message")
        for handler in self.root_logger.handlers:
            handler.flush()

    @staticmethod
    def _capture_levels(project: Path):
        captures = list((project / ".cgull" / "logs").glob("scan-*.log"))
        if len(captures) != 1:
            raise AssertionError(f"expected one automatic capture, got {captures!r}")
        return [
            json.loads(line)["level"]
            for line in captures[0].read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_full_logging_sink_matrix(self):
        cases = (
            ("default", 0, None, False, False, ["WARNING", "ERROR"]),
            ("info", 1, None, False, False, ["INFO", "WARNING", "ERROR"]),
            ("debug", 2, None, False, False, ["DEBUG", "INFO", "WARNING", "ERROR"]),
            (
                "trace",
                3,
                None,
                False,
                False,
                ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"],
            ),
            ("error", 0, "error", False, False, ["ERROR"]),
            ("text-default", 0, None, True, False, ["WARNING", "ERROR"]),
            (
                "text-debug",
                2,
                None,
                True,
                False,
                ["DEBUG", "INFO", "WARNING", "ERROR"],
            ),
            ("no-log", 0, None, False, True, ["WARNING", "ERROR"]),
            (
                "text-trace-no-log",
                3,
                None,
                True,
                True,
                ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"],
            ),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for name, verbose, explicit_level, use_text, no_log, expected in cases:
                with self.subTest(name=name):
                    project = root / name
                    project.mkdir()
                    text_log = project / "explicit.log"
                    stderr = io.StringIO()
                    with patch("sys.stderr", stderr):
                        configure_logging(
                            verbose_count=verbose,
                            log_level_str=explicit_level,
                            log_file=str(text_log) if use_text else None,
                            no_log=no_log,
                            project_state_root=str(project),
                        )
                        self._emit_levels()

                    if no_log:
                        self.assertFalse((project / ".cgull" / "logs").exists())
                    else:
                        self.assertEqual(self._capture_levels(project), expected)

                    if use_text:
                        text = text_log.read_text(encoding="utf-8")
                        for level in ("trace", "debug", "info", "warning", "error"):
                            self.assertEqual(f"{level}-message" in text, level.upper() in expected)
                    else:
                        self.assertFalse(text_log.exists())

                    stderr_text = stderr.getvalue()
                    for level in ("trace", "debug", "info", "warning", "error"):
                        self.assertEqual(
                            f"{level}-message" in stderr_text,
                            level.upper() in expected,
                        )

    def test_global_and_scan_logging_option_positions_are_equivalent(self):
        parser = build_parser()
        global_args = parser.parse_args(
            ["-vv", "--log-file", "diag.log", "--no-log", "scan", "sample.c"]
        )
        scan_args = parser.parse_args(
            ["scan", "-vv", "--log-file", "diag.log", "--no-log", "sample.c"]
        )

        for args in (global_args, scan_args):
            self.assertEqual(args.verbose, 2)
            self.assertEqual(args.log_file, "diag.log")
            self.assertTrue(args.no_log)
            self.assertEqual(args.command, "scan")
            self.assertEqual(args.target, ["sample.c"])

    def test_global_no_log_does_not_hide_init_or_preprocessor_command(self):
        self.assertEqual(_command_after_global_options(["--no-log", "init"]), "init")
        self.assertEqual(
            _command_after_global_options(["-vv", "--no-log", "preprocessor"]),
            "preprocessor",
        )
        self.assertEqual(
            _command_after_global_options(
                ["--log-level=debug", "--no-log", "preprocessor"]
            ),
            "preprocessor",
        )

    def test_explicit_text_log_path_error_remains_fatal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(OSError):
                configure_logging(
                    log_file=tmpdir,
                    no_log=True,
                    project_state_root=tmpdir,
                )

    def test_structured_stdout_is_not_contaminated_by_logging(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            source = project / "clean.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

            for report_format in ("json", "sarif", "markdown"):
                with self.subTest(report_format=report_format):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                        rc = main(
                            [
                                "scan",
                                str(source),
                                "-q",
                                "--no-log",
                                "--format",
                                report_format,
                            ]
                        )
                    self.assertEqual(rc, 0)
                    payload = stdout.getvalue()
                    if report_format in ("json", "sarif"):
                        json.loads(payload)
                    else:
                        self.assertTrue(payload.lstrip().startswith("#"))
                    self.assertNotIn("cgull.issue456", payload)
                    self.assertNotIn("TRACE", payload)
                    self.assertNotIn("DEBUG", payload)


if __name__ == "__main__":
    unittest.main()
