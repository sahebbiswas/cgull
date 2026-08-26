"""
Structured trace and diagnostic logging configuration for C-GULL.
"""

import logging
import time
import sys
from typing import Optional, Union

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


def configure_logging(
    verbose_count: int = 0,
    log_level_str: Optional[str] = None,
    log_file: Optional[str] = None,
) -> None:
    """
    Configures root logging with a standard structured format.
    """
    # Determine log level
    if log_level_str:
        level = parse_log_level(log_level_str)
    elif verbose_count >= 3:
        level = TRACE_LEVEL_NUM
    elif verbose_count == 2:
        level = logging.DEBUG
    elif verbose_count == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    # If unconfigured/default WARNING level or quiet logging, use raw message format
    # so unformatted direct stderr error messages like "\n[ERROR] Analysis failed for ..."
    # remain prefixed by newline and exactly match terminal expectations without timestamp prefixes.
    if level >= logging.WARNING and not log_file and verbose_count == 0 and not log_level_str:
        fmt = "%(message)s"
    else:
        fmt = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    formatter = UTCFormatter(fmt)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to avoid duplicates on re-configuration
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

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
) -> None:
    """
    Configures root logging with a standard structured format.
    """
    # Determine log level
    if log_level_str:
        level = parse_log_level(log_level_str)
    elif verbose_count >= 3:
        level = TRACE_LEVEL_NUM
    elif verbose_count == 2:
        level = logging.DEBUG
    elif verbose_count == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    # If unconfigured/default WARNING level or quiet logging, use raw message format
    # so unformatted direct stderr error messages like "\n[ERROR] Analysis failed for ..."
    # remain prefixed by newline and exactly match terminal expectations without timestamp prefixes.
    if level >= logging.WARNING and not log_file and verbose_count == 0 and not log_level_str:
        fmt = "%(message)s"
    else:
        fmt = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    formatter = UTCFormatter(fmt)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to avoid duplicates on re-configuration
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

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
