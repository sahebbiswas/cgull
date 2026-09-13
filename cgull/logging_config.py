"""
Structured trace and diagnostic logging configuration for C-GULL.
"""

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .project_state import DEFAULT_LOG_RETENTION_RUNS

# Define TRACE level below DEBUG (DEBUG is 10)
TRACE_LEVEL_NUM = 5
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")

_DEFAULT_CAPTURE_RE = re.compile(
    r"^scan-(?P<stamp>\d{8}T\d{6}(?:\.\d{1,6})?Z)-(?P<pid>\d+)\.log$"
)
_BOOTSTRAP_PROJECT_STATE_ROOT: Optional[str] = None
_BOOTSTRAP_RETENTION_RUNS: Optional[int] = None


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


def set_logging_bootstrap_context(
    *,
    project_state_root: Optional[str] = None,
    retention_runs: Optional[int] = None,
) -> None:
    """Set transient CLI-derived state used by the legacy logging call site."""
    global _BOOTSTRAP_PROJECT_STATE_ROOT, _BOOTSTRAP_RETENTION_RUNS
    _BOOTSTRAP_PROJECT_STATE_ROOT = project_state_root
    _BOOTSTRAP_RETENTION_RUNS = retention_runs


def clear_logging_bootstrap_context() -> None:
    """Clear transient CLI logging state after one command dispatch."""
    set_logging_bootstrap_context(project_state_root=None, retention_runs=None)


def _capture_sort_key(path: Path):
    match = _DEFAULT_CAPTURE_RE.match(path.name)
    if match is not None:
        stamp = match.group("stamp")
        for fmt in ("%Y%m%dT%H%M%S.%fZ", "%Y%m%dT%H%M%SZ"):
            try:
                parsed = datetime.strptime(stamp, fmt).replace(tzinfo=timezone.utc)
                return (parsed.timestamp(), path.name)
            except ValueError:
                continue
    try:
        return (path.stat().st_mtime_ns / 1_000_000_000, path.name)
    except OSError:
        return (0.0, path.name)


def _default_capture_files(log_dir: Path):
    if not log_dir.is_dir():
        return []
    return sorted(
        (
            child
            for child in log_dir.iterdir()
            if child.is_file() and _DEFAULT_CAPTURE_RE.match(child.name)
        ),
        key=_capture_sort_key,
    )


def _prune_default_capture_logs(log_dir: Path, retention_runs: int) -> None:
    """Make room for the current run while deleting only C-GULL-owned captures."""
    keep_existing = max(retention_runs - 1, 0)
    captures = _default_capture_files(log_dir)
    excess = len(captures) - keep_existing
    if excess <= 0:
        return
    for capture in captures[:excess]:
        capture.unlink()


def _display_logging_warning(
    stderr_handler: DynamicStderrHandler,
    message: str,
    args,
) -> None:
    warning = logging.LogRecord(
        "cgull.logging",
        logging.WARNING,
        __file__,
        0,
        message,
        args,
        None,
    )
    stderr_handler.handle(warning)


def configure_logging(
    verbose_count: int = 0,
    log_level_str: Optional[str] = None,
    log_file: Optional[str] = None,
    capture_file: Optional[str] = None,
    project_state_root: Optional[str] = None,
    retention_runs: Optional[int] = None,
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

    # Optional legacy text log handler. Its level continues to follow display
    # verbosity until the compatibility/opt-out slice in #456 extends CLI policy.
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    auto_capture = capture_file is None
    warning_emitted = False

    if auto_capture:
        state_root = project_state_root or _BOOTSTRAP_PROJECT_STATE_ROOT or os.getcwd()
        configured_retention = (
            retention_runs
            if retention_runs is not None
            else _BOOTSTRAP_RETENTION_RUNS
        )
        if (
            isinstance(configured_retention, bool)
            or not isinstance(configured_retention, int)
            or configured_retention <= 0
        ):
            configured_retention = DEFAULT_LOG_RETENTION_RUNS

        log_dir = Path(state_root) / ".cgull" / "logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            _prune_default_capture_logs(log_dir, configured_retention)
        except OSError as exc:
            _display_logging_warning(
                stderr_handler,
                "Unable to prune diagnostic capture logs in %s: %s",
                (str(log_dir), exc),
            )
            warning_emitted = True

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        capture_file = str(log_dir / f"scan-{stamp}-{os.getpid()}.log")

    try:
        capture_path = Path(capture_file)
        capture_path.parent.mkdir(parents=True, exist_ok=True)
        capture_handler = logging.FileHandler(
            capture_path,
            mode="x" if auto_capture else "a",
            encoding="utf-8",
        )
        capture_handler.setLevel(TRACE_LEVEL_NUM)
        capture_handler.setFormatter(JSONLFormatter())
        root_logger.addHandler(capture_handler)
    except (OSError, ValueError) as exc:
        # Report through the already-configured display handler, never through a
        # partially initialized capture handler. Suppress a second setup warning
        # if retention already failed during this same bootstrap.
        if not warning_emitted:
            _display_logging_warning(
                stderr_handler,
                "Unable to create diagnostic capture log %s: %s",
                (capture_file, exc),
            )


def teardown_cli_logging() -> None:
    """Flush, close, and detach file and diagnostic capture handlers for CLI runs."""
    root_logger = logging.getLogger()
    for h in list(root_logger.handlers):
        if isinstance(h, logging.FileHandler):
            root_logger.removeHandler(h)
            try:
                h.flush()
            except Exception:
                pass
            try:
                h.close()
            except Exception:
                pass
