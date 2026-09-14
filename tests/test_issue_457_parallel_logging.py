"""Regression coverage for coordinator-owned multiprocessing logging (#457)."""

from concurrent.futures import ProcessPoolExecutor
import io
import json
import logging
import multiprocessing
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cgull.engine import CGullScanner, _scan_file_worker
import cgull.logging_config as logging_config
from cgull.logging_config import configure_logging, multiprocessing_logging_context
from cgull.models import ScanConfig


class TestIssue457ParallelLogging(unittest.TestCase):
    def setUp(self):
        self.root_logger = logging.getLogger()
        self.original_handlers = list(self.root_logger.handlers)
        self.original_level = self.root_logger.level
        self.original_stderr = sys.stderr
        self.temp_dir = tempfile.mkdtemp()
        self.source_dir = os.path.join(self.temp_dir, "src")
        os.makedirs(self.source_dir)

        # Keep each task non-trivial so jobs=2 reliably schedules work on both
        # processes without relying on cross-worker record ordering.
        body = "\n".join(
            f"int issue457_f{i}(char *b) {{ gets(b); return {i}; }}"
            for i in range(24)
        )
        for index in range(6):
            with open(
                os.path.join(self.source_dir, f"worker_{index}.c"),
                "w",
                encoding="utf-8",
            ) as stream:
                stream.write(body + "\n")

    def tearDown(self):
        sys.stderr = self.original_stderr
        self.root_logger.setLevel(self.original_level)
        for handler in list(self.root_logger.handlers):
            self.root_logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass
        for handler in self.original_handlers:
            if handler not in self.root_logger.handlers:
                self.root_logger.addHandler(handler)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @staticmethod
    def _records(path):
        with open(path, encoding="utf-8") as stream:
            return [json.loads(line) for line in stream if line.strip()]

    def test_parallel_default_creates_one_capture_and_filters_worker_detail(self):
        configure_logging(project_state_root=self.temp_dir)

        result = CGullScanner().scan_path(self.source_dir, jobs=2)

        self.assertEqual(result.files_analyzed, 6)
        log_dir = Path(self.temp_dir) / ".cgull" / "logs"
        captures = sorted(log_dir.glob("scan-*.log"))
        self.assertEqual(len(captures), 1)
        records = self._records(captures[0])
        self.assertTrue(
            all(record["level"] in {"WARNING", "ERROR", "CRITICAL"} for record in records)
        )
        self.assertFalse(
            any("Entering file scan:" in record["message"] for record in records)
        )
        self.assertFalse(
            any("Executing regex rule" in record["message"] for record in records)
        )

    def test_parallel_trace_preserves_worker_pids_and_drains_before_return(self):
        capture_file = os.path.join(self.temp_dir, "parallel-trace.log")
        configure_logging(verbose_count=3, capture_file=capture_file)
        coordinator_pid = os.getpid()

        result = CGullScanner().scan_path(self.source_dir, jobs=2)

        self.assertEqual(result.files_analyzed, 6)
        records = self._records(capture_file)
        worker_records = [
            record
            for record in records
            if "Entering file scan:" in record["message"]
        ]
        self.assertGreaterEqual(len(worker_records), 6)
        worker_pids = {record["process_id"] for record in worker_records}
        self.assertNotIn(coordinator_pid, worker_pids)
        self.assertGreaterEqual(len(worker_pids), 2)

        # scan_path returns only after the logging context exits. Seeing every
        # worker's terminal INFO record here proves QueueListener.stop() drained
        # records before the caller regained control.
        leaving = [
            record
            for record in records
            if "Leaving file scan:" in record["message"]
        ]
        self.assertEqual(len(leaving), 6)
        self.assertTrue(any(record["level"] == "TRACE" for record in records))

    def test_spawn_worker_error_is_queued_once_and_honors_error_override(self):
        capture_file = os.path.join(self.temp_dir, "spawn-error.log")
        stderr_buffer = io.StringIO()
        missing = os.path.join(self.temp_dir, "missing.c")
        coordinator_pid = os.getpid()

        with patch("sys.stderr", stderr_buffer):
            configure_logging(
                verbose_count=3,
                log_level_str="error",
                capture_file=capture_file,
            )
            with multiprocessing_logging_context() as (log_queue, log_level):
                self.assertIsNotNone(log_queue)
                ctx = multiprocessing.get_context("spawn")
                with ProcessPoolExecutor(max_workers=1, mp_context=ctx) as pool:
                    worker_result = pool.submit(
                        _scan_file_worker,
                        missing,
                        ScanConfig.create(),
                        None,
                        False,
                        False,
                        log_queue,
                        log_level,
                    ).result()

        self.assertEqual(worker_result[5], "failed")
        records = self._records(capture_file)
        self.assertTrue(records)
        self.assertTrue(
            all(record["level"] in {"ERROR", "CRITICAL"} for record in records)
        )
        worker_errors = [
            record
            for record in records
            if record["level"] == "ERROR"
            and record["process_id"] != coordinator_pid
            and "Analysis failed for" in record["message"]
        ]
        self.assertEqual(len(worker_errors), 1)

        # _emit_error also writes raw stderr. The spawn worker must suppress that
        # direct path, leaving only the coordinator listener's rendered record.
        self.assertEqual(stderr_buffer.getvalue().count("Analysis failed for"), 1)

    def test_transport_setup_failure_warns_once_and_restores_worker_marker(self):
        stderr_buffer = io.StringIO()
        marker = logging_config._WORKER_LOGGING_ENV
        previous = os.environ.get(marker)

        with patch("sys.stderr", stderr_buffer):
            configure_logging(no_log=True)
            with patch(
                "cgull.logging_config.multiprocessing.Manager",
                side_effect=OSError("manager unavailable"),
            ):
                with multiprocessing_logging_context() as (log_queue, _level):
                    self.assertIsNone(log_queue)
                    self.assertEqual(os.environ.get(marker), "1")

        self.assertEqual(
            stderr_buffer.getvalue().count("Parallel diagnostic transport unavailable"),
            1,
        )
        self.assertEqual(os.environ.get(marker), previous)

    def test_worker_marker_refcounts_overlapping_threads(self):
        marker = logging_config._WORKER_LOGGING_ENV
        previous = os.environ.get(marker)
        both_acquired = threading.Barrier(3)
        release_first = threading.Event()
        release_second = threading.Event()
        errors = []

        def hold_marker(release_event):
            try:
                logging_config._acquire_worker_logging_marker()
                both_acquired.wait(timeout=5)
                release_event.wait(timeout=5)
            except BaseException as exc:  # surface thread failures in the test
                errors.append(exc)
            finally:
                logging_config._release_worker_logging_marker()

        first = threading.Thread(target=hold_marker, args=(release_first,))
        second = threading.Thread(target=hold_marker, args=(release_second,))
        first.start()
        second.start()
        try:
            both_acquired.wait(timeout=5)
            self.assertEqual(os.environ.get(marker), "1")

            release_first.set()
            first.join(timeout=5)
            self.assertFalse(first.is_alive())
            self.assertEqual(os.environ.get(marker), "1")

            release_second.set()
            second.join(timeout=5)
            self.assertFalse(second.is_alive())
            self.assertFalse(errors)
            self.assertEqual(os.environ.get(marker), previous)
        finally:
            release_first.set()
            release_second.set()
            first.join(timeout=5)
            second.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
