"""
Shared lexical utilities for C-GULL.

Centralizes comment/string-literal handling and inline suppression-comment
parsing so that every rule (regex or AST based) sees the same, correctly
masked view of the source -- rather than each rule re-implementing its own
(inconsistent) comment/string handling.
"""

import hashlib
import re
import sys
from typing import Dict, List, Optional, Set, TextIO, Tuple

# Matches: // cgull-ignore
#          // cgull-ignore: CGULL-001
#          // cgull-ignore: CGULL-001,CGULL-003
#          // cgull-ignore-next-line
#          // cgull-disable-next-line CGULL-007
#          // cgull-disable-line CGULL-019
#          /* cgull-disable-next-line: CGULL-001,CGULL-003 */
_SUPPRESS_RE = re.compile(
    r'(?:cgull-ignore|cgull-disable)(?P<next>-next-line)?(?P<line>-line)?(?:\s*[:\s]\s*(?P<ids>[A-Za-z0-9_,\-\s]+))?',
    re.IGNORECASE,
)


def strip_comments_keep_lines(source: str) -> Tuple[List[str], str]:
    """
    Strips block comments /* */ and line comments // while preserving exact
    line breaks, column offsets, and string/char literal contents.

    This is the single source of truth for comment stripping; both the
    regex engine and the AST parser use it so that a banned-function name
    or keyword appearing only inside a comment can never trigger a rule.
    """
    output_chars = []
    i = 0
    n = len(source)
    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False

    while i < n:
        c = source[i]
        next_c = source[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if c == "\n":
                in_line_comment = False
                output_chars.append("\n")
            else:
                output_chars.append(" ")
            i += 1
            continue

        if in_block_comment:
            if c == "*" and next_c == "/":
                in_block_comment = False
                output_chars.append("  ")
                i += 2
            elif c == "\n":
                output_chars.append("\n")
                i += 1
            else:
                output_chars.append(" ")
                i += 1
            continue

        if in_string:
            output_chars.append(c)
            if c == "\\" and i + 1 < n:
                output_chars.append(source[i + 1])
                i += 2
                continue
            elif c == '"':
                in_string = False
            i += 1
            continue

        if in_char:
            output_chars.append(c)
            if c == "\\" and i + 1 < n:
                output_chars.append(source[i + 1])
                i += 2
                continue
            elif c == "'":
                in_char = False
            i += 1
            continue

        if c == "/" and next_c == "/":
            in_line_comment = True
            output_chars.append("  ")
            i += 2
            continue

        if c == "/" and next_c == "*":
            in_block_comment = True
            output_chars.append("  ")
            i += 2
            continue

        if c == '"':
            in_string = True
            output_chars.append(c)
            i += 1
            continue

        if c == "'":
            in_char = True
            output_chars.append(c)
            i += 1
            continue

        output_chars.append(c)
        i += 1

    clean_code = "".join(output_chars)
    clean_lines = clean_code.splitlines()
    return clean_lines, clean_code


def mask_string_and_char_literals(line: str) -> str:
    """
    Replaces the *contents* of string/char literals with 'x' placeholders,
    preserving quotes, length, and escape-sequence backslashes.

    Used by call-pattern rules (banned functions, atoi, etc.) so that a
    function name appearing only as text inside a string literal --
    e.g. char *msg = "please don't use gets()"; -- is not mistaken for an
    actual call. Length is preserved so column numbers stay valid, and
    downstream rules that legitimately need to know "is this a string
    literal" (e.g. format-string literal detection) still see the quotes.
    """
    out = []
    i = 0
    n = len(line)
    in_string = False
    in_char = False
    while i < n:
        c = line[i]
        if in_string or in_char:
            quote = '"' if in_string else "'"
            if c == "\\" and i + 1 < n:
                out.append("\\")
                out.append("x")
                i += 2
                continue
            if c == quote:
                out.append(c)
                if in_string:
                    in_string = False
                else:
                    in_char = False
                i += 1
                continue
            out.append("x")
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == "'":
            in_char = True
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def is_in_string_or_char_literal(line: str, index: int) -> bool:
    """Returns True if `index` in raw `line` falls inside a string/char literal."""
    in_string = False
    in_char = False
    i = 0
    n = min(index, len(line))
    while i < n:
        c = line[i]
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
        elif in_char:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                in_char = False
        else:
            if c == '"':
                in_string = True
            elif c == "'":
                in_char = True
        i += 1
    return in_string or in_char


class SuppressionMap:
    """
    Tracks which (line_number, rule_id) pairs should be suppressed based on
    `cgull-ignore` directives found in comments in the original source.

    Supports:
      // cgull-ignore                (suppress all rules on this line)
      // cgull-ignore: CGULL-001     (suppress specific rule(s) on this line)
      // cgull-ignore-next-line      (suppress all rules on the NEXT line)
      // cgull-ignore-next-line: CGULL-001,CGULL-003
    """

    def __init__(self) -> None:
        # line_number -> set of rule_ids, or {"*"} for "suppress everything"
        self._same_line: Dict[int, Set[str]] = {}
        self._next_line: Dict[int, Set[str]] = {}

    @classmethod
    def from_source(cls, raw_lines: List[str]) -> "SuppressionMap":
        sup = cls()
        for line_no, raw_line in enumerate(raw_lines, 1):
            line_lower = raw_line.lower()
            if "cgull-ignore" not in line_lower and "cgull-disable" not in line_lower:
                continue
            for m in _SUPPRESS_RE.finditer(raw_line):
                ids_raw = m.group("ids")
                if ids_raw:
                    rule_ids = set()
                    for token in ids_raw.split(","):
                        cleaned = token.strip().rstrip("*/").strip().upper()
                        if cleaned:
                            rule_ids.add(cleaned)
                    if not rule_ids:
                        rule_ids = {"*"}
                else:
                    rule_ids = {"*"}

                if m.group("next"):
                    sup._next_line.setdefault(line_no + 1, set()).update(rule_ids)
                else:
                    sup._same_line.setdefault(line_no, set()).update(rule_ids)
        return sup

    def is_suppressed(self, line_number: int, rule_id: str) -> bool:
        for bucket in (self._same_line, self._next_line):
            rule_ids = bucket.get(line_number)
            if rule_ids and ("*" in rule_ids or rule_id.upper() in rule_ids):
                return True
        return False


# Collapses all runs of whitespace to a single space and trims the ends, so
# a finding's fingerprint survives pure re-indentation / reformatting of
# the line it was found on.
_WHITESPACE_RUN_RE = re.compile(r'\s+')


def compute_issue_fingerprint(rule_id: str, relative_file_path: str, code_snippet: str) -> str:
    """
    Computes a stable identifier for a finding, used to recognize "the same
    issue" across two separate scans (baseline diffing) and to populate
    SARIF's partialFingerprints (so tools like GitHub Code Scanning can
    track a finding's lifecycle across commits instead of treating every
    run as all-new).

    Deliberately content-based rather than line-number-based: an unrelated
    edit earlier in the file that shifts every subsequent line number
    would otherwise make every later finding look "new" to a line-number
    based diff. Whitespace is normalized so pure reformatting/re-indenting
    doesn't do the same. This is a heuristic, not a cryptographic
    guarantee -- two textually-identical lines flagged by the same rule
    in the same file will collide (deliberately: from a baseline/dedup
    perspective, they *are* the same finding to act on).
    """
    normalized_path = relative_file_path.replace("\\", "/")
    normalized_snippet = _WHITESPACE_RUN_RE.sub(" ", code_snippet.strip())
    basis = f"{rule_id}|{normalized_path}|{normalized_snippet}"
    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()[:16]


class ProgressIndicator:
    """
    In-place CLI progress indicator for file scanning.
    Writes progress to sys.stderr (or custom stream) using carriage return (\r).
    When finished, erases the line completely so output remains clean.
    """

    def __init__(
        self,
        stream: Optional[TextIO] = None,
        quiet: bool = False,
        bar_width: int = 20,
    ) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.quiet = quiet
        self.bar_width = bar_width
        self.last_line_len = 0

    def update(self, completed: int, total: int, current_file: str = "") -> None:
        if self.quiet:
            return

        if total <= 0:
            percentage = 100
            filled_len = self.bar_width
        else:
            percentage = min(100, int((completed / total) * 100))
            filled_len = min(self.bar_width, int(self.bar_width * completed / total))

        bar = "█" * filled_len + "░" * (self.bar_width - filled_len)
        file_disp = f" {current_file}" if current_file else ""
        line = f"Scanning [{bar}] {percentage}% ({completed}/{total} files){file_disp}"

        padded_line = line.ljust(self.last_line_len)
        self.stream.write(f"\r{padded_line}")
        self.stream.flush()
        self.last_line_len = max(self.last_line_len, len(padded_line))

    def finish(self) -> None:
        if self.quiet:
            return
        if self.last_line_len > 0:
            self.stream.write("\r" + " " * self.last_line_len + "\r")
            self.stream.flush()
            self.last_line_len = 0
