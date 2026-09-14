"""Safe structured payload helpers for persistent C-GULL diagnostics."""

import json
import logging
import math
import os
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import PurePath
from typing import Any, Optional, Set, Tuple


LOG_SOURCE_EXCERPT_LIMIT = 768
"""Maximum serialized length of a source-derived logging excerpt."""

_TRUNCATION_MARKER = "... [truncated]"
_CONTEXT_STRING_LIMIT = 1000
_MAX_NESTING_DEPTH = 8


def _safe_text(value: Any) -> str:
    """Return text for arbitrary values without allowing ``__str__`` to fail logging."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, PurePath):
        # Persistent structured logs use one path spelling across platforms while
        # preserving relative-vs-absolute semantics and avoiding path resolution.
        return value.as_posix()
    if isinstance(value, os.PathLike):
        try:
            path_value = os.fspath(value)
            if isinstance(path_value, bytes):
                return path_value.decode("utf-8", errors="replace")
            return str(path_value)
        except Exception:
            pass
    try:
        return str(value)
    except Exception:
        try:
            return repr(value)
        except Exception:
            value_type = type(value)
            return f"<unprintable {value_type.__module__}.{value_type.__qualname__}>"


def _bound_context_text(text: str, limit: int = _CONTEXT_STRING_LIMIT) -> str:
    """Bound non-message context while preserving the existing truncation marker."""
    if len(text) <= limit:
        return text
    return text[:limit] + _TRUNCATION_MARKER


def truncate_log_excerpt(value: Any) -> Tuple[str, bool]:
    """Normalize and bound a source-derived excerpt for durable diagnostic logs.

    Control characters, including CR/LF/tab, become spaces so an excerpt cannot
    introduce visual line ambiguity after a JSONL record is decoded. The returned
    text is at most ``LOG_SOURCE_EXCERPT_LIMIT`` characters including the visible
    truncation marker.
    """
    text = _safe_text(value)
    normalized = "".join(char if char.isprintable() else " " for char in text)
    if len(normalized) <= LOG_SOURCE_EXCERPT_LIMIT:
        return normalized, False
    keep = max(LOG_SOURCE_EXCERPT_LIMIT - len(_TRUNCATION_MARKER), 0)
    return normalized[:keep] + _TRUNCATION_MARKER, True


def _stable_sort_key(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def safe_json_value(
    value: Any,
    *,
    _seen: Optional[Set[int]] = None,
    _depth: int = 0,
) -> Any:
    """Convert practical logging context values into deterministic JSON values."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else _safe_text(value)
    if isinstance(value, Enum):
        return safe_json_value(value.value, _seen=_seen, _depth=_depth + 1)
    if isinstance(value, str):
        return _bound_context_text(value)
    if isinstance(value, (bytes, bytearray, memoryview, os.PathLike)):
        return _bound_context_text(_safe_text(value))

    if _depth >= _MAX_NESTING_DEPTH:
        return _bound_context_text(_safe_text(value))

    if _seen is None:
        _seen = set()

    traversable = (
        (is_dataclass(value) and not isinstance(value, type))
        or isinstance(value, (Mapping, list, tuple, set, frozenset))
    )
    object_id = id(value)
    if traversable:
        if object_id in _seen:
            return f"<recursive {type(value).__name__}>"
        _seen.add(object_id)

    try:
        if is_dataclass(value) and not isinstance(value, type):
            return {
                field.name: safe_json_value(
                    getattr(value, field.name),
                    _seen=_seen,
                    _depth=_depth + 1,
                )
                for field in fields(value)
            }
        if isinstance(value, Mapping):
            return {
                _bound_context_text(_safe_text(key)): safe_json_value(
                    item,
                    _seen=_seen,
                    _depth=_depth + 1,
                )
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [
                safe_json_value(item, _seen=_seen, _depth=_depth + 1)
                for item in value
            ]
        if isinstance(value, (set, frozenset)):
            converted = [
                safe_json_value(item, _seen=_seen, _depth=_depth + 1)
                for item in value
            ]
            return sorted(converted, key=_stable_sort_key)
        return _bound_context_text(_safe_text(value))
    finally:
        if traversable:
            _seen.discard(object_id)


def _safe_timestamp(record: logging.LogRecord) -> str:
    try:
        created = float(record.created)
        if not math.isfinite(created):
            raise ValueError("non-finite timestamp")
        instant = datetime.fromtimestamp(created, timezone.utc)
    except Exception:
        instant = datetime.fromtimestamp(0, timezone.utc)
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_message(record: logging.LogRecord) -> str:
    try:
        return record.getMessage()
    except Exception as exc:
        return (
            _safe_text(getattr(record, "msg", ""))
            + f" [message formatting failed: {type(exc).__name__}]"
        )


def _safe_exception(record: logging.LogRecord) -> Optional[str]:
    if not record.exc_info:
        return None
    exc_type, exc_value, _ = record.exc_info
    type_name = getattr(exc_type, "__name__", None) or _safe_text(exc_type)
    if exc_value is None:
        return type_name
    message = _bound_context_text(_safe_text(exc_value))
    return f"{type_name}: {message}" if message else type_name


def _safe_bool(value: Any) -> bool:
    try:
        return bool(value)
    except Exception:
        return True


class JSONLFormatter(logging.Formatter):
    """Render one total, explicit, parseable JSON object per log record.

    Unknown ``LogRecord`` extras are intentionally omitted. Only the documented
    ``cgull_*`` context fields below are part of the persistent compatibility
    surface.
    """

    _CONTEXT_FIELDS = (
        "cgull_phase",
        "cgull_file",
        "cgull_rule",
        "cgull_function",
        "cgull_profile",
    )

    def format(self, record: logging.LogRecord) -> str:
        try:
            payload = {
                "timestamp": _safe_timestamp(record),
                "level": _safe_text(getattr(record, "levelname", "ERROR")),
                "logger": _safe_text(getattr(record, "name", "cgull.logging")),
                "message": _safe_message(record),
                "process_id": safe_json_value(getattr(record, "process", 0)),
            }
            for field in self._CONTEXT_FIELDS:
                if hasattr(record, field):
                    payload[field] = safe_json_value(getattr(record, field))

            if hasattr(record, "cgull_excerpt"):
                excerpt, truncated = truncate_log_excerpt(
                    getattr(record, "cgull_excerpt")
                )
                payload["cgull_excerpt"] = excerpt
                payload["cgull_excerpt_truncated"] = truncated or _safe_bool(
                    getattr(record, "cgull_excerpt_truncated", False)
                )
            elif hasattr(record, "cgull_excerpt_truncated"):
                payload["cgull_excerpt_truncated"] = _safe_bool(
                    getattr(record, "cgull_excerpt_truncated")
                )

            exception = _safe_exception(record)
            if exception is not None:
                payload["exception"] = exception

            return json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except Exception:
            # A formatter defect must never terminate analysis. This fallback uses
            # only bounded/safe primitives and a stable timestamp derived from the
            # record when possible.
            return json.dumps(
                {
                    "timestamp": _safe_timestamp(record),
                    "level": _safe_text(getattr(record, "levelname", "ERROR")),
                    "logger": _safe_text(getattr(record, "name", "cgull.logging")),
                    "message": "Unable to serialize diagnostic record",
                    "process_id": safe_json_value(getattr(record, "process", 0)),
                },
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
