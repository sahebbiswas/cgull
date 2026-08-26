"""
Unit tests for C-GULL structured trace logging and CLI log controls.
"""

import os
import sys
import io
import shutil
import tempfile
import logging
import unittest
from unittest.mock import patch

from cgull.logging_config import configure_logging, parse_log_level, TRACE_LEVEL_NUM
from cgull.cli import main, handle_scan, build_parser
from cgull.engine import CGullScanner


class TestLoggingConfig(unittest.TestCase):
    def setUp(self):
        self.root_logger = logging.getLogger()
        self.original_handlers = list(self.root_logger.handlers)
        self.original_level = self.root_logger.level

    def tearDown(self):
        self.root_logger.setLevel(self.original_level)
        for h in list(self.root_logger.handlers):
            self.root_logger.removeHandler(h)
        for h in self.original_handlers:
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
        configure_logging(verbose_count=0)
        self.assertEqual(self.root_logger.level, logging.WARNING)

        configure_logging(verbose_count=1)
        self.assertEqual(self.root_logger.level, logging.INFO)

        configure_logging(verbose_count=2)
        self.assertEqual(self.root_logger.level, logging.DEBUG)

        configure_logging(verbose_count=3)
        self.assertEqual(self.root_logger.level, TRACE_LEVEL_NUM)

    def test_configure_logging_log_level_string_takes_precedence(self):
        configure_logging(verbose_count=1, log_level_str="trace")
        self.assertEqual(self.root_logger.level, TRACE_LEVEL_NUM)

        configure_logging(verbose_count=3, log_level_str="error")
        self.assertEqual(self.root_logger.level, logging.ERROR)

    def test_configure_logging_log_file(self):
        temp_dir = tempfile.mkdtemp()
        try:
            log_file = os.path.join(temp_dir, "cgull_test.log")
            configure_logging(verbose_count=1, log_file=log_file)

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
            shutil.rmtree(temp_dir, ignore_errors=True)


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
        for h in self.original_handlers:
            self.root_logger.addHandler(h)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_trace_level_logs_per_rule_invocation(self):
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            configure_logging(verbose_count=3)
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
        with patch("sys.stderr", stderr_buf), patch("sys.stdout", stdout_buf):
            exit_code = main(["scan", self.sample_c, "-vvv", "--log-file", log_file])

        self.assertEqual(exit_code, 0)
        self.assertTrue(os.path.exists(log_file))
        with open(log_file, "r", encoding="utf-8") as f:
            log_content = f.read()

        self.assertIn("TRACE    cgull.engine: Executing regex rule", log_content)
        self.assertIn("INFO     cgull.engine: Starting scan of target path", log_content)


if __name__ == "__main__":
    unittest.main()
