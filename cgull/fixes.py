"""Safe source-fix application for C-GULL findings."""

from __future__ import annotations

from dataclasses import dataclass, field
import difflib
import os
from typing import Dict, Iterable, List, Tuple

from .models import FixType, Issue


@dataclass
class FixConflict:
    file_path: str
    line_number: int
    reason: str


@dataclass
class FixResult:
    eligible_issues: int = 0
    replacements: int = 0
    files_changed: int = 0
    conflicts: List[FixConflict] = field(default_factory=list)
    diffs: List[str] = field(default_factory=list)


def _newline_for(line: str) -> str:
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n"):
        return "\n"
    if line.endswith("\r"):
        return "\r"
    return ""


def _render_replacement(original_line: str, replacement: str) -> str:
    newline = _newline_for(original_line)
    body = original_line[:-len(newline)] if newline else original_line
    indent = body[: len(body) - len(body.lstrip())]
    replacement_lines = replacement.splitlines() or [""]
    rendered = newline.join(indent + part for part in replacement_lines)
    return rendered + newline


def apply_safe_fixes(issues: Iterable[Issue], *, write: bool = False) -> FixResult:
    """Preview or apply non-conflicting ``SAFE_FIX`` whole-line replacements.

    The current Issue schema identifies a line and replacement text, but not a
    byte range. Consequently fixes are intentionally line-granular. Multiple
    identical fixes on one line are deduplicated; differing replacements for
    the same file/line are skipped as conflicts.
    """
    result = FixResult()
    grouped: Dict[Tuple[str, int], List[Issue]] = {}

    for issue in issues:
        if issue.fix_type != FixType.SAFE_FIX or issue.auto_fix_replacement is None:
            continue
        result.eligible_issues += 1
        grouped.setdefault((issue.file_path, issue.line_number), []).append(issue)

    by_file: Dict[str, Dict[int, List[Issue]]] = {}
    for (path, line_no), line_issues in grouped.items():
        by_file.setdefault(path, {})[line_no] = line_issues

    for path, line_groups in sorted(by_file.items()):
        if not os.path.isfile(path):
            for line_no in line_groups:
                result.conflicts.append(FixConflict(path, line_no, "source file is unavailable"))
            continue

        with open(path, "r", encoding="utf-8", errors="surrogateescape", newline="") as handle:
            original = handle.read()
        lines = original.splitlines(keepends=True)
        changed = list(lines)
        file_replacements = 0

        for line_no, line_issues in sorted(line_groups.items()):
            replacements = {issue.auto_fix_replacement for issue in line_issues}
            if len(replacements) != 1:
                result.conflicts.append(FixConflict(path, line_no, "conflicting SAFE_FIX replacements"))
                continue
            if line_no < 1 or line_no > len(lines):
                result.conflicts.append(FixConflict(path, line_no, "line number is outside the source file"))
                continue

            original_line = lines[line_no - 1]
            snippets = {issue.code_snippet.strip() for issue in line_issues if issue.code_snippet.strip()}
            if snippets and original_line.strip() not in snippets:
                result.conflicts.append(FixConflict(path, line_no, "source line no longer matches the finding"))
                continue

            replacement = next(iter(replacements))
            changed[line_no - 1] = _render_replacement(original_line, replacement)
            file_replacements += 1

        if not file_replacements:
            continue

        updated = "".join(changed)
        if updated == original:
            continue

        result.replacements += file_replacements
        result.files_changed += 1
        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=path,
                tofile=path,
            )
        )
        result.diffs.append(diff)

        if write:
            with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as handle:
                handle.write(updated)

    return result
