"""Regression coverage for hardened structured logging payloads (#458)."""

import io
import json
import logging
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from unittest.mock import patch

from cgull.logging_config import JSONLFormatter
from cgull.logging_payload import (
    LOG_SOURCE_EXCERPT_LIMIT,
    truncate_log_excerpt,
)
from cgull.parse_diagnostics import make_attempt, map_attempts


class _Mode(Enum):
    FAST = "fast"


@dataclass(frozen=True)
class _Profile:
    root: Path
    mode: _Mode
    threshold: float


class _Unsupported:
    def __str__(self):
        return "unsupported-value"


class _ExplodingString:
    def __str__(self):
        raise RuntimeError("no string")

    def __repr__(self):
        return "<exploding-string>"


def _record(message="message", exc_info=None):
    return logging.LogRecord(
        "cgull.issue458",
        logging.WARNING,
        "test_issue_458_logging_payloads.py",
        1,
        message,
        (),
        exc_info,
    )


def test_explicit_context_surface_omits_unknown_extras():
    record = _record("héllo\nworld\t\x00")
    record.cgull_phase = "parse"
    record.cgull_file = Path("src/naïve.c")
    record.cgull_rule = _Unsupported()
    record.cgull_function = b"fn\xff"
    record.cgull_profile = _Profile(Path("profiles/α"), _Mode.FAST, float("nan"))
    record.framework_internal = _ExplodingString()

    formatted = JSONLFormatter().format(record)
    assert "\n" not in formatted
    parsed = json.loads(formatted)

    assert parsed["message"] == "héllo\nworld\t\x00"
    assert parsed["cgull_phase"] == "parse"
    assert parsed["cgull_file"] == "src/naïve.c"
    assert parsed["cgull_rule"] == "unsupported-value"
    assert parsed["cgull_function"] == "fn�"
    assert parsed["cgull_profile"] == {
        "mode": "fast",
        "root": "profiles/α",
        "threshold": "nan",
    }
    assert "framework_internal" not in parsed


def test_unprintable_allowed_extra_cannot_break_jsonl():
    record = _record()
    record.cgull_rule = _ExplodingString()
    record.cgull_profile = {
        "positive": float("inf"),
        "negative": float("-inf"),
    }

    parsed = json.loads(JSONLFormatter().format(record))
    assert parsed["cgull_rule"] == "<exploding-string>"
    assert parsed["cgull_profile"] == {
        "negative": "-inf",
        "positive": "inf",
    }


def test_exception_stays_inside_one_json_object():
    try:
        raise ValueError("bad\nvalue")
    except ValueError:
        record = _record("failed", sys.exc_info())

    formatted = JSONLFormatter().format(record)
    assert "\n" not in formatted
    parsed = json.loads(formatted)
    assert parsed["exception"] == "ValueError: bad\nvalue"


def test_source_excerpt_is_normalized_bounded_and_flagged():
    source = "A" * (LOG_SOURCE_EXCERPT_LIMIT + 40) + "\r\n\t\x00tail"
    excerpt, truncated = truncate_log_excerpt(source)

    assert truncated is True
    assert len(excerpt) == LOG_SOURCE_EXCERPT_LIMIT
    assert excerpt.endswith("... [truncated]")
    assert all(char.isprintable() for char in excerpt)

    record = _record()
    record.cgull_excerpt = source
    parsed = json.loads(JSONLFormatter().format(record))
    assert parsed["cgull_excerpt"] == excerpt
    assert parsed["cgull_excerpt_truncated"] is True


def test_short_source_excerpt_is_unchanged_and_not_truncated():
    record = _record()
    record.cgull_excerpt = "return café;"

    parsed = json.loads(JSONLFormatter().format(record))
    assert parsed["cgull_excerpt"] == "return café;"
    assert parsed["cgull_excerpt_truncated"] is False


def test_caller_truncation_flag_is_preserved_for_prebounded_excerpt():
    record = _record()
    record.cgull_excerpt = "already bounded"
    record.cgull_excerpt_truncated = True

    parsed = json.loads(JSONLFormatter().format(record))
    assert parsed["cgull_excerpt"] == "already bounded"
    assert parsed["cgull_excerpt_truncated"] is True


def test_parser_diagnostic_snippet_uses_same_central_excerpt_bound():
    source = "Z" * (LOG_SOURCE_EXCERPT_LIMIT + 100)
    attempt = make_attempt(
        "directive-stripped",
        "failure",
        ValueError("<input>:1:1: bad"),
        prepared=source,
        source=source,
    )

    mapped = map_attempts([attempt], source, file_path="input.c")[0]
    expected, truncated = truncate_log_excerpt(source)
    assert truncated is True
    assert mapped["snippet"] == expected
    assert len(mapped["snippet"]) == LOG_SOURCE_EXCERPT_LIMIT


def test_filtered_debug_record_never_invokes_excerpt_helper():
    logger = logging.getLogger("cgull.issue458.filtered")
    original_handlers = list(logger.handlers)
    original_level = logger.level
    original_propagate = logger.propagate
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.WARNING)
    handler.setFormatter(JSONLFormatter())
    try:
        logger.handlers = [handler]
        logger.setLevel(logging.WARNING)
        logger.propagate = False
        with patch("cgull.logging_payload.truncate_log_excerpt") as helper:
            logger.debug("hidden", extra={"cgull_excerpt": "source detail"})
            helper.assert_not_called()
        assert stream.getvalue() == ""
    finally:
        logger.handlers = original_handlers
        logger.setLevel(original_level)
        logger.propagate = original_propagate
        handler.close()


def test_repeated_formatting_of_same_record_is_stable():
    record = _record("stable")
    record.created = 1_700_000_000.125
    record.cgull_profile = {"b": 2, "a": 1}
    formatter = JSONLFormatter()

    assert formatter.format(record) == formatter.format(record)
