"""Bounded parser-attempt metadata shared by parser, workers, and reporters."""

import os
import re
from typing import Any, Dict, List, Optional


def sanitize(value: Any, limit: Optional[int] = 240) -> str:
    """Keep diagnostic text on one printable, bounded line."""
    return ' '.join(''.join(c if c.isprintable() else ' ' for c in str(value)).split())[:limit]


def sanitize_path(value: str) -> str:
    """Preserve printable path characters, including repeated spaces."""
    return ''.join(c if c.isprintable() else ' ' for c in value)


def make_attempt(tier: str, status: str, error: Optional[Exception] = None,
                 prelude_lines: int = 0, preprocessing_failed: bool = False,
                 prepared: str = "", source: str = "") -> Dict[str, Any]:
    message = str(error) if error is not None else ''
    match = re.match(r'^.*?:(\d+)(?::(\d+))?:\s*(.*)', message, re.DOTALL)
    line = int(match[1]) if match else None
    column = int(match[2]) if match and match[2] else None
    reason = match[3] if match else message
    source_line = line - prelude_lines if line and line > prelude_lines else None
    prepared_lines, source_lines = prepared.splitlines(), source.splitlines()
    same_line = bool(line and source_line and line <= len(prepared_lines)
                     and source_line <= len(source_lines)
                     and prepared_lines[line - 1] == source_lines[source_line - 1])
    return dict(tier=tier, status=status,
                exception_category=type(error).__name__ if error is not None else None,
                message=sanitize(reason), expanded_line=line, expanded_column=column,
                source_line=source_line, source_column=column if same_line else None,
                original_file=None, original_line=None, original_column=None,
                preprocessing_failed=preprocessing_failed, snippet='')


def map_attempts(attempts: List[Dict[str, Any]], source: str,
                 line_map=None, file_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Resolve line provenance; retain columns only when source text is unchanged.

    TU provenance is line-granular. Macro expansion and normalization can change
    columns, so an unverified original column remains null.
    """
    lines = source.splitlines()
    result = []
    for attempt in attempts:
        item = dict(attempt)
        line = item['source_line']
        loc = (line_map or {}).get(line)
        text = lines[line - 1] if line and 0 < line <= len(lines) else ''
        item['original_file'] = sanitize_path(loc.file_path if loc else file_path) if loc or file_path else None
        item['original_line'] = loc.line_number if loc else line
        item['snippet'] = sanitize(loc.line_content if loc else text, 160)
        item['original_column'] = item.get('source_column') if not loc or loc.line_content == text else None
        result.append(item)
    return result


def report_attempts(attempts: List[Dict[str, Any]], base_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    result = []
    for attempt in attempts:
        item = dict(attempt)
        path = item.get('original_file')
        if path and base_dir:
            item['original_file'] = sanitize_path(os.path.relpath(path, base_dir))
        result.append(item)
    return result


def format_attempts(file_path: str, attempts: List[Dict[str, Any]]) -> str:
    reasons = []
    for item in attempts:
        if item['status'] == 'success':
            continue
        location = sanitize(item.get('original_file') or file_path, 500)
        if item.get('original_line'):
            location += ':' + str(item['original_line'])
        if item.get('original_column'):
            location += ':' + str(item['original_column'])
        reasons.append(f"{item['tier']} {item['status']} at {location}: "
                       f"{item['message'] or item['exception_category'] or 'preprocessing unavailable'}")
    return sanitize(file_path, 500) + ' used regex-fallback: ' + '; '.join(reasons)
