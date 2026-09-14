"""Verified lexical write locations for degraded dead-store analysis.

Rule coordinates stay in the expanded input. Provenance is retained separately;
only the scanner's TU output boundary restores original locations and snippets.
"""

from dataclasses import dataclass
import re
from typing import Any, Optional, Tuple

from ..utils import mask_string_and_char_literals


@dataclass(frozen=True)
class FallbackWrite:
    binding: Tuple[str, int, int]
    function: str
    expanded_line: int
    column: int
    kind: str
    statement: str
    original_location: Any = None


class WriteSource:
    """Index source once; no per-candidate scans of the remaining function."""

    def __init__(self, context):
        self.lines = context.clean_source.splitlines()
        self.source = "\n".join(self.lines)
        self.masked = "\n".join(mask_string_and_char_literals(line) for line in self.lines)
        self.offsets = []
        offset = 0
        for line in self.lines:
            self.offsets.append(offset)
            offset += len(line) + 1


def verified_write(context, function, variable, line: int, source: WriteSource) -> Optional[FallbackWrite]:
    """Associate a candidate with an exact scalar write, or withhold it.

    Line-only data cannot prove evaluation order for arbitrary compact C. Accept
    a single statement, plus the established initializer/overwrite idiom, and
    decline ambiguous compound statements, member writes and malformed input.
    """
    if not 1 <= line <= len(source.lines):
        return None
    name = re.escape(variable.name)
    start = source.offsets[line - 1]
    stop = source.offsets[function.end_line] if function.end_line < len(source.lines) else len(source.source)
    end = source.masked.find(';', start, stop)
    if end < 0:
        return None
    first_line_end = start + len(source.lines[line - 1])
    text = source.source[start:max(end + 1, first_line_end)]
    masked = source.masked[start:max(end + 1, first_line_end)]
    end -= start
    first_line_end -= start
    statement = text[:end + 1]
    code = masked[:end + 1]
    declaration = line == variable.declaration_line and variable.has_initializer
    if declaration:
        match = re.match(rf"\s*(?:[A-Za-z_]\w*\s+)+[*\s]*{name}\s*(?:\[[^;]*?\]\s*)?=(?!=)", code)
        kind = "initializer"
    else:
        match = re.match(rf"\s*{name}\s*(?P<op>(?:<<|>>|[+\-*/%&|^])?=)(?!=)", code)
        kind = "assignment" if match and match.group('op') == '=' else "compound_assignment"
    if match is None:
        return None
    depth = 0
    for char in code[match.end():]:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == ',' and depth == 0:
            return None

    # Never accept a previous brace/call/blank line as a write's starting line.
    if not code.splitlines()[0].strip():
        return None
    column = len(code) - len(code.lstrip()) + 1
    tail = masked[end + 1:first_line_end].strip()
    if tail:
        # Preserve the common compact initializer followed by one plain write.
        # More complex compact statements lack reliable read/write ordering.
        overwrite = re.fullmatch(rf"{name}\s*=(?!=)\s*([^;]*);", tail)
        if not declaration or overwrite is None or re.search(rf"\b{name}\b", overwrite.group(1)):
            return None
        kind = "assignment"
        column = end + 2 + len(masked[end + 1:first_line_end]) - len(masked[end + 1:first_line_end].lstrip())
        statement = text[end + 1:first_line_end].strip()
    return FallbackWrite(
        (variable.name, variable.enclosing_block_id, variable.declaration_line),
        function.name, line, column, kind, statement.strip(),
        (context.line_map or {}).get(line),
    )
