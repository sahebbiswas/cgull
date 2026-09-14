"""
Unit tests for C-GULL structured trace logging and CLI log controls.
"""

import os
import sys
import io
import json
import shutil
import tempfile
import logging
import unittest
from unittest.mock import patch
from contextlib import contextmanager

from cgull.logging_config import (
    DynamicStderrHandler,
    JSONLFormatter,
    configure_logging,
    parse_log_level,
    TRACE_LEVEL_NUM,
)
from cgull.cli import main, handle_scan, build_parser
from cgull.engine import CGullScanner


@contextmanager
def logging_directory():
    """Release file handles before temporary-directory cleanup on Windows."""
    with tempfile.TemporaryDirectory() as directory:
        try:
            yield directory
        finally:
            root = logging.getLogger()
            for handler in list(root.handlers):
                if isinstance(handler, logging.FileHandler):
                    root.removeHandler(handler)
                    stream = handler.stream
                    handler.close()
                    assert stream is None or stream.closed




class TestLoggingConfig(unittest.TestCase):
    def setUp(self):
        self.root_logger = logging.getLogger()
        self.original_handlers = list(self.root_logger.handlers)
        self.original_level = self.root_logger.level

    def tearDown(self):
        self.root_logger.setLevel(self.original_level)
        for h in list(self.root_logger.handlers):
            self.root_logger.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass
        for h in self.original_handlers:
            if not isinstance(h, logging.FileHandler):
                self.root_logger.addHandler(h)

    def test_parse_log_level(self):
        self.assertEqual(parse_log_level("trace"), TRACE_LEVEL_NUM)
        self.assertEqual(parse_log_level("debug"), logging.DEBUG)
        self.assertEqual(parse_log_level("info"), logging.INFO)
        self.assertEqual(parse_log_level("warning"), logging.WARNING)
        self.assertEqual(parse_log_level("warn"), logging.WARNING)
        self.assertEqual(parse_log_level("error"), logging.ERROR)
        self.assertEqual(parse_log_level("critical"), logging.CRITICAL)
        self.assertEqual(parse_log_level("15"), 15)
        self.assertEqual(parse_log_level("invalid"), logging.WARNING)

    def test_configure_logging_verbose_levels(self):
        with logging_directory() as temp_dir:
            for count, expected in (
                (0, logging.WARNING),
                (1, logging.INFO),
                (2, logging.DEBUG),
                (3, TRACE_LEVEL_NUM),
            ):
                configure_logging(
                    verbose_count=count,
                    capture_file=os.path.join(temp_dir, f"capture-{count}.log"),
                )
                stderr = next(
                    h for h in self.root_logger.handlers
                    if isinstance(h, DynamicStderrHandler)
                )
                capture = next(
                    h for h in self.root_logger.handlers
                    if isinstance(h.formatter, JSONLFormatter)
                )
                self.assertEqual(stderr.level, expected)
                self.assertEqual(capture.level, expected)
                self.assertEqual(self.root_logger.level, expected)

    def test_configure_logging_log_level_string_takes_precedence(self):
        with logging_directory() as temp_dir:
            configure_logging(
                verbose_count=1,
                log_level_str="trace",
                capture_file=os.path.join(temp_dir, "trace.log"),
            )
            stderr = next(
                h
                for h in self.root_logger.handlers
                if isinstance(h, DynamicStderrHandler)
            )
            self.assertEqual(stderr.level, TRACE_LEVEL_NUM)

            configure_logging(
                verbose_count=3,
                log_level_str="error",
                capture_file=os.path.join(temp_dir, "error.log"),
            )
            stderr = next(
                h
                for h in self.root_logger.handlers
                if isinstance(h, DynamicStderrHandler)
            )
            self.assertEqual(stderr.level, logging.ERROR)

    def test_capture_records_selected_levels_as_jsonl(self):
        with logging_directory() as temp_dir:
            capture_file = os.path.join(temp_dir, "capture.log")
            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                configure_logging(log_level_str="warning", capture_file=capture_file)
                logger = logging.getLogger("cgull.capture_test")
                logger.log(TRACE_LEVEL_NUM, "trace")
                logger.debug("debug")
                logger.info("info")
                logger.warning(
                    "warning",
                    extra={"cgull_phase": "parse", "cgull_rule": "CGULL-001"},
                )
                logger.error("error")
                for handler in self.root_logger.handlers:
                    handler.flush()

            with open(capture_file, encoding="utf-8") as stream:
                records = [json.loads(line) for line in stream]
            self.assertEqual(
                [record["level"] for record in records],
                ["WARNING", "ERROR"],
            )
            self.assertEqual(records[0]["cgull_phase"], "parse")
            self.assertEqual(records[0]["cgull_rule"], "CGULL-001")
            self.assertIn("warning", stderr_buf.getvalue())
            self.assertIn("error", stderr_buf.getvalue())

    def test_exception_is_one_json_record(self):
        with logging_directory() as temp_dir:
            capture_file = os.path.join(temp_dir, "capture.log")
            configure_logging(capture_file=capture_file)
            try:
                raise ValueError("bad value")
            except ValueError:
                logging.getLogger("cgull.capture_test").exception("failed")
            for handler in self.root_logger.handlers:
                handler.flush()
            with open(capture_file, encoding="utf-8") as stream:
                lines = stream.readlines()
            self.assertEqual(len(lines), 1)
            self.assertIn("ValueError: bad value", json.loads(lines[0])["exception"])

    def test_explicit_capture_path_can_be_reused(self):
        with logging_directory() as temp_dir:
            capture_file = os.path.join(temp_dir, "capture.log")
            with open(capture_file, "w", encoding="utf-8") as stream:
                stream.write('{"message": "existing"}\n')
            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                configure_logging(capture_file=capture_file)
                old_handler = next(
                    h for h in self.root_logger.handlers
                    if isinstance(h.formatter, JSONLFormatter)
                )
                old_stream = old_handler.stream
                logging.getLogger("cgull.capture_test").warning("first")
                configure_logging(capture_file=capture_file)
                self.assertTrue(old_stream.closed)
                logging.getLogger("cgull.capture_test").warning("second")
            captures = [
                h for h in self.root_logger.handlers
                if isinstance(h.formatter, JSONLFormatter)
            ]
            self.assertEqual(len(captures), 1)
            captures[0].flush()
            with open(capture_file, encoding="utf-8") as stream:
                messages = [json.loads(line)["message"] for line in stream]
            self.assertEqual(messages, ["existing", "first", "second"])
            self.assertIn("first", stderr_buf.getvalue())
            self.assertIn("second", stderr_buf.getvalue())

    def test_capture_open_failure_warns_and_remains_usable(self):
        stderr_buf = io.StringIO()
        with logging_directory() as temp_dir:
            directory = os.path.join(temp_dir, "not-a-file")
            os.mkdir(directory)
            with patch("sys.stderr", stderr_buf):
                configure_logging(capture_file=directory)
                logging.getLogger("cgull.capture_test").error("still works")
        self.assertEqual(
            stderr_buf.getvalue().count("Unable to create diagnostic capture"), 1
        )
        self.assertIn("still works", stderr_buf.getvalue())

    def test_configure_logging_log_file(self):
        temp_dir = tempfile.mkdtemp()
        try:
            log_file = os.path.join(temp_dir, "cgull_test.log")
            configure_logging(
                verbose_count=1,
                log_file=log_file,
                capture_file=os.path.join(temp_dir, "capture.log"),
            )

            test_logger = logging.getLogger("cgull.test_module")
            test_logger.info("Test log entry into file")

            # Flush handlers
            for h in self.root_logger.handlers:
                h.flush()

            self.assertTrue(os.path.exists(log_file))
            with open(log_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("INFO     cgull.test_module: Test log entry into file", content)
        finally:
            for handler in list(self.root_logger.handlers):
                if isinstance(handler, logging.FileHandler):
                    self.root_logger.removeHandler(handler)
                    handler.close()
            shutil.rmtree(temp_dir)


class TestLoggingV2(unittest.TestCase):
    def setUp(self):
        self.root_logger = logging.getLogger()
        self.original_handlers = list(self.root_logger.handlers)
        self.original_level = self.root_logger.level
        self.temp_dir = tempfile.mkdtemp()
        self.sample_c1 = os.path.join(self.temp_dir, "sample1.c")
        self.sample_c2 = os.path.join(self.temp_dir, "sample2.c")
        with open(self.sample_c1, "w") as f:
            f.write("int main(void) { char b[10]; gets(b); return 0; }\n")
        with open(self.sample_c2, "w") as f:
            f.write("int foo(void) { char b[20]; strcpy(b, \"hello\"); return 0; }\n")

    def tearDown(self):
        self.root_logger.setLevel(self.original_level)
        for h in list(self.root_logger.handlers):
            self.root_logger.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass
        for h in self.original_handlers:
            self.root_logger.addHandler(h)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_no_log_disables_automatic_capture(self):
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            configure_logging(
                no_log=True,
                project_state_root=self.temp_dir,
            )
            logging.getLogger("cgull.test_nolog").warning("warning msg")

        logs_dir = os.path.join(self.temp_dir, ".cgull", "logs")
        self.assertFalse(os.path.exists(logs_dir))

    def test_no_log_combined_with_log_file(self):
        log_file = os.path.join(self.temp_dir, "text_only.log")
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            configure_logging(
                no_log=True,
                log_file=log_file,
                project_state_root=self.temp_dir,
            )
            logging.getLogger("cgull.test_nolog").warning("written to text file")
            for h in self.root_logger.handlers:
                h.flush()

        logs_dir = os.path.join(self.temp_dir, ".cgull", "logs")
        self.assertFalse(os.path.exists(logs_dir))
        self.assertTrue(os.path.exists(log_file))
        with open(log_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("written to text file", content)

    def test_cli_no_log_flag(self):
        stderr_buf = io.StringIO()
        stdout_buf = io.StringIO()
        previous_cwd = os.getcwd()
        try:
            os.chdir(self.temp_dir)
            with patch("sys.stderr", stderr_buf), patch("sys.stdout", stdout_buf):
                exit_code = main(["scan", self.temp_dir, "--no-log"])
        finally:
            os.chdir(previous_cwd)

        self.assertEqual(exit_code, 0)
        logs_dir = os.path.join(self.temp_dir, ".cgull", "logs")
        self.assertFalse(os.path.exists(logs_dir))

    def test_quiet_does_not_imply_no_log(self):
        stderr_buf = io.StringIO()
        stdout_buf = io.StringIO()
        previous_cwd = os.getcwd()
        try:
            os.chdir(self.temp_dir)
            with patch("sys.stderr", stderr_buf), patch("sys.stdout", stdout_buf):
                exit_code = main(["scan", self.temp_dir, "-q"])
        finally:
            os.chdir(previous_cwd)

        self.assertEqual(exit_code, 0)
        logs_dir = os.path.join(self.temp_dir, ".cgull", "logs")
        self.assertTrue(os.path.exists(logs_dir))
        captures = list(os.listdir(logs_dir))
        self.assertEqual(len(captures), 1)

    def test_parallel_worker_logging_forwarding(self):
        capture_file = os.path.join(self.temp_dir, "parallel_capture.log")
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            configure_logging(
                verbose_count=1,
                capture_file=capture_file,
            )
            scanner = CGullScanner()
            result = scanner.scan_path(self.temp_dir, jobs=2)

        self.assertEqual(result.scanned_files_count, 2)
        self.assertTrue(os.path.exists(capture_file))
        with open(capture_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        # Verify each line is a valid JSON object
        records = [json.loads(line) for line in lines]
        self.assertGreater(len(records), 0)
        for rec in records:
            self.assertIn("timestamp", rec)
            self.assertIn("level", rec)
            self.assertIn("message", rec)

    def test_jsonl_formatter_bounded_fields_and_control_chars(self):
        formatter = JSONLFormatter()
        record = logging.LogRecord(
            "cgull.bounded_test",
            logging.WARNING,
            "test.py",
            42,
            "msg with\nnewline and\rreturn and\ttab",
            (),
            None,
        )
        record.cgull_file = "A" * 2000
        formatted = formatter.format(record)

        self.assertNotIn("\n", formatted)
        parsed = json.loads(formatted)
        self.assertEqual(parsed["message"], "msg with\nnewline and\rreturn and\ttab")
        self.assertTrue(parsed["cgull_file"].endswith("... [truncated]"))
        self.assertEqual(len(parsed["cgull_file"]), 1000 + len("... [truncated]"))


class TestTriageTraceLogging(unittest.TestCase):
    def setUp(self):
        self.root_logger = logging.getLogger()
        self.original_handlers = list(self.root_logger.handlers)
        self.original_level = self.root_logger.level
        self.temp_dir = tempfile.mkdtemp()
        self.sample_c = os.path.join(self.temp_dir, "sample.c")
        with open(self.sample_c, "w") as f:
            f.write("int main(void) { char b[10]; gets(b); return 0; }\n")

    def tearDown(self):
        self.root_logger.setLevel(self.original_level)
        for h in list(self.root_logger.handlers):
            self.root_logger.removeHandler(h)
            h.close()
        for h in self.original_handlers:
            self.root_logger.addHandler(h)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_trace_level_logs_per_rule_invocation(self):
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            configure_logging(
                verbose_count=3,
                capture_file=os.path.join(self.temp_dir, "capture.log"),
            )
            scanner = CGullScanner()
            result = scanner.scan_path(self.sample_c)

        output = stderr_buf.getvalue()
        self.assertIn("TRACE", output)
        self.assertIn("Executing regex rule CGULL-001", output)
        self.assertIn("Entering file scan:", output)
        self.assertIn("Leaving file scan:", output)

    def test_cli_verbose_and_log_file_options(self):
        log_file = os.path.join(self.temp_dir, "trace.log")
        stderr_buf = io.StringIO()
        stdout_buf = io.StringIO()
        previous_cwd = os.getcwd()
        try:
            os.chdir(self.temp_dir)
            with patch("sys.stderr", stderr_buf), patch("sys.stdout", stdout_buf):
                exit_code = main(
                    ["scan", self.sample_c, "-vvv", "--log-file", log_file]
                )
        finally:
            os.chdir(previous_cwd)

        self.assertEqual(exit_code, 0)
        self.assertTrue(os.path.exists(log_file))
        with open(log_file, "r", encoding="utf-8") as f:
            log_content = f.read()

        self.assertIn("TRACE    cgull.engine: Executing regex rule", log_content)
        self.assertIn("INFO     cgull.engine: Starting scan of target path", log_content)


if __name__ == "__main__":
    unittest.main()
