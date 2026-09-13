"""
Structured trace and diagnostic logging configuration for C-GULL.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Define TRACE level below DEBUG (DEBUG is 10)
TRACE_LEVEL_NUM = 5
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")


def trace(self, message, *args, **kws):
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)


# Attach trace method to logging.Logger if not already attached
if not hasattr(logging.Logger, "trace"):
    logging.Logger.trace = trace


class UTCFormatter(logging.Formatter):
    """
    Formatter that uses UTC ISO 8601 timestamps.
    """
    converter = time.gmtime

    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt:
            s = time.strftime(datefmt, ct)
        else:
            t = time.strftime("%Y-%m-%dT%H:%M:%S", ct)
            s = f"{t}.{int(record.msecs):03d}Z"
        return s


def parse_log_level(level_str: str) -> int:
    """
    Parses string log level to logging level integer.
    Supports: error, warning, info, debug, trace (case-insensitive).
    """
    normalized = level_str.strip().lower()
    if normalized == "trace":
        return TRACE_LEVEL_NUM
    elif normalized == "debug":
        return logging.DEBUG
    elif normalized == "info":
        return logging.INFO
    elif normalized == "warning" or normalized == "warn":
        return logging.WARNING
    elif normalized == "error":
        return logging.ERROR
    elif normalized == "critical":
        return logging.CRITICAL
    else:
        try:
            return int(normalized)
        except ValueError:
            return logging.WARNING


def _resolve_display_level(verbose_count: int, log_level_str: Optional[str]) -> int:
    if log_level_str:
        return parse_log_level(log_level_str)
    if verbose_count >= 3:
        return TRACE_LEVEL_NUM
    if verbose_count == 2:
        return logging.DEBUG
    if verbose_count == 1:
        return logging.INFO
    return logging.WARNING


class JSONLFormatter(logging.Formatter):
    """Render one structured, parseable JSON object per log record."""

    _CONTEXT_FIELDS = ("cgull_phase", "cgull_file", "cgull_rule")

    def format(self, record: logging.LogRecord) -> str:
        try:
            payload = {
                "timestamp": (
                    datetime.fromtimestamp(record.created, timezone.utc)
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z")
                ),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "process_id": record.process,
            }
            for field in self._CONTEXT_FIELDS:
                if hasattr(record, field):
                    value = getattr(record, field)
                    try:
                        json.dumps(value, allow_nan=False)
                    except (TypeError, ValueError):
                        value = str(value)
                    payload[field] = value
            if record.exc_info:
                payload["exception"] = self.formatException(record.exc_info)
            return json.dumps(payload, ensure_ascii=False, allow_nan=False)
        except Exception:
            # Logging must never be allowed to terminate analysis. Keep the
            # fallback deliberately small and composed only of safe primitives.
            return json.dumps(
                {
                    "timestamp": datetime.now(timezone.utc)
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z"),
                    "level": getattr(record, "levelname", "ERROR"),
                    "logger": getattr(record, "name", "cgull.logging"),
                    "message": "Unable to serialize diagnostic record",
                    "process_id": os.getpid(),
                }
            )


class _ProgressSafeStderr:
    """Coordinate ordinary stderr writes with C-GULL's in-place progress line.

    ProgressIndicator renders with carriage returns while diagnostics and logging
    use normal stderr writes.  When both target the same interactive terminal, an
    uncoordinated diagnostic permanently leaves the current progress line behind.
    This proxy remembers the most recent progress rendering, clears it before an
    ordinary stderr write, and redraws it afterwards. Redirected streams are passed
    through unchanged so files, pipes, and CI logs never gain terminal control
    sequences.
    """

    def __init__(self, stream):
        self._stream = stream
        self._progress_line = ""
        self._progress_width = 0

    def __getattr__(self, name):
        return getattr(self._stream, name)

    def _is_tty(self) -> bool:
        isatty = getattr(self._stream, "isatty", None)
        if not callable(isatty):
            return False
        try:
            return bool(isatty())
        except OSError:
            return False

    def write(self, data):
        if not data:
            return 0

        # Carriage-return progress coordination is meaningful only on an
        # interactive terminal. Preserve redirected stderr byte-for-byte.
        if not self._is_tty():
            return self._stream.write(data)

        # Both the base and telemetry progress indicators begin their in-place
        # rendering with a carriage return and the stable "Scanning [" prefix.
        if data.startswith("\rScanning ["):
            self._progress_line = data
            self._progress_width = max(
                self._progress_width,
                len(data[1:]),
            )
            return self._stream.write(data)

        # ProgressIndicator.finish() erases the in-place line with only carriage
        # returns/spaces.  Treat that as ownership ending rather than as a
        # diagnostic that should trigger a redraw.
        if self._progress_line and data.startswith("\r") and data.endswith("\r"):
            if not data.strip("\r "):
                self._progress_line = ""
                self._progress_width = 0
                return self._stream.write(data)

        if not self._progress_line:
            return self._stream.write(data)

        progress_line = self._progress_line
        width = self._progress_width
        self._stream.write("\r" + " " * width + "\r")
        self._stream.write(data)
        # A partial-line write cannot safely be followed by a carriage-return
        # progress redraw without overwriting the diagnostic text. Once progress
        # is erased for a partial write, forget the remembered rendering so any
        # subsequent chunks append to that visible diagnostic instead of erasing it.
        if data.endswith("\n"):
            self._stream.write(progress_line)
        else:
            self._progress_line = ""
            self._progress_width = 0
        return len(data)

    def flush(self):
        return self._stream.flush()


def _ensure_progress_safe_stderr() -> None:
    """Install the stderr coordinator once for CLI/logging output."""
    if isinstance(sys.stderr, _ProgressSafeStderr):
        return
    sys.stderr = _ProgressSafeStderr(sys.stderr)


class DynamicStderrHandler(logging.StreamHandler):
    """
    StreamHandler whose stream dynamically evaluates sys.stderr at emit time
    so that sys.stderr patching in tests is respected.
    """
    @property
    def stream(self):
        return sys.stderr

    @stream.setter
    def stream(self, value):
        pass


def configure_logging(
    verbose_count: int = 0,
    log_level_str: Optional[str] = None,
    log_file: Optional[str] = None,
    capture_file: Optional[str] = None,
) -> None:
    """Configure interactive display and complete local diagnostic capture."""
    _ensure_progress_safe_stderr()
    level = _resolve_display_level(verbose_count, log_level_str)

    # If unconfigured/default WARNING level or quiet logging, use raw message format
    # so unformatted direct stderr error messages like "\n[ERROR] Analysis failed for ..."
    # remain prefixed by newline and exactly match terminal expectations without timestamp prefixes.
    if level >= logging.WARNING and not log_file and verbose_count == 0 and not log_level_str:
        fmt = "%(message)s"
    else:
        fmt = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    formatter = UTCFormatter(fmt)

    root_logger = logging.getLogger()
    root_logger.setLevel(TRACE_LEVEL_NUM)

    # Close replaced file handlers as well as detaching them; repeated calls are
    # common in the API test suite and must not leak descriptors.
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass

    stderr_handler = DynamicStderrHandler()
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(formatter)
    root_logger.addHandler(stderr_handler)

    # Optional Log file handler
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # #455 will supply the canonical project-state location and retention. This
    # dependency-first slice uses a safe project-local default.
    auto_capture = capture_file is None
    if auto_capture:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        capture_file = str(
            Path.cwd() / ".cgull" / "logs" / f"scan-{stamp}-{os.getpid()}.log"
        )
    try:
        capture_path = Path(capture_file)
        capture_path.parent.mkdir(parents=True, exist_ok=True)
        # Reserve a new path without allowing FileHandler's lazy/re-open path to
        # repeat exclusive creation in forked test/scan processes. Coordinator-
        # owned queue transport replaces inherited handlers in #457.
        if auto_capture:
            capture_path.touch(exist_ok=False)
        capture_handler = logging.FileHandler(capture_path, mode="a", encoding="utf-8")
        capture_handler.setLevel(TRACE_LEVEL_NUM)
        capture_handler.setFormatter(JSONLFormatter())
        root_logger.addHandler(capture_handler)
    except (OSError, ValueError) as exc:
        # Report through the already-configured display handler, never through a
        # partially initialized capture handler.
        warning = logging.LogRecord(
            "cgull.logging",
            logging.WARNING,
            __file__,
            0,
            "Unable to create diagnostic capture log %s: %s",
            (capture_file, exc),
            None,
        )
        stderr_handler.handle(warning)
