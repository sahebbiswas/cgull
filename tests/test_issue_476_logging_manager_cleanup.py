"""Regression coverage for multiprocessing logging setup cleanup in PR #476."""

import logging

import cgull.logging_config as logging_config


def test_multiprocessing_logging_context_shuts_down_manager_on_setup_failure(
    monkeypatch,
):
    """A partially initialized Manager must not leak its child process."""

    class FailingManager:
        def __init__(self):
            self.shutdown_called = False

        def Queue(self):
            raise RuntimeError("queue setup failed")

        def shutdown(self):
            self.shutdown_called = True

    manager = FailingManager()
    monkeypatch.setattr(logging_config.multiprocessing, "Manager", lambda: manager)

    root_logger = logging.getLogger()
    handler = logging.NullHandler()
    root_logger.addHandler(handler)
    try:
        with logging_config.multiprocessing_logging_context() as (log_queue, _level):
            assert log_queue is None
        assert manager.shutdown_called
    finally:
        root_logger.removeHandler(handler)
