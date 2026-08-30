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
import logging
from typing import Dict, List, Optional, Set, TextIO, Tuple, Any

logger = logging.getLogger(__name__)


# Matches: // cgull-ignore
#          // cgull-ignore: CGULL-001
#          // cgull-ignore: CGULL-001,CGULL-003
#          // cgull-ignore-next-line
#          // cgull-disable-next-line CGULL-007
#          // cgull-disable-line CGULL-019
#          /* cgull-disable-next-line: CGULL-001,CGULL-003 */
_ANSI_RE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
_CONTROL_CHAR_RE = re.compile(r'[\x00-\x1f\x7f]')


def sanitize_terminal_text(text: str) -> str:
    """
    Strips ANSI escape sequences, replaces newlines and carriage returns with spaces,
    and strips control characters from text before writing to terminal/stderr.
    """
    s = _ANSI_RE.sub("", text)
    s = s.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    s = _CONTROL_CHAR_RE.sub("", s)
    return s


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


def extract_balanced_parens(text: str, start_paren_pos: int) -> Tuple[Optional[str], int]:
    """
    Given `text` and position of opening '(', returns `(inside_str, closing_paren_pos)`.
    Handles nested parentheses, string literals, character literals, and escape sequences.
    If parentheses are unclosed or start_paren_pos is invalid, returns (None, len(text)).
    """
    if start_paren_pos < 0 or start_paren_pos >= len(text) or text[start_paren_pos] != '(':
        return None, start_paren_pos

    paren_depth = 0
    in_string = False
    in_char = False
    escape = False
    j = start_paren_pos
    n = len(text)

    while j < n:
        c = text[j]
        if escape:
            escape = False
        elif c == '\\':
            escape = True
        elif c == '"' and not in_char:
            in_string = not in_string
        elif c == "'" and not in_string:
            in_char = not in_char
        elif not in_string and not in_char:
            if c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth -= 1
                if paren_depth == 0:
                    return text[start_paren_pos + 1 : j], j
        j += 1

    return None, j


def split_call_args(raw_args: str) -> List[str]:
    """
    Splits top-level comma-separated arguments from a raw argument string (without enclosing parens).
    Handles nested parentheses, brackets, braces, string/char literals, and escape sequences.
    """
    if not raw_args or not raw_args.strip():
        return []

    args: List[str] = []
    curr: List[str] = []
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    in_string = False
    in_char = False
    escape = False

    for c in raw_args:
        if escape:
            curr.append(c)
            escape = False
        elif c == '\\':
            curr.append(c)
            escape = True
        elif c == '"' and not in_char:
            in_string = not in_string
            curr.append(c)
        elif c == "'" and not in_string:
            in_char = not in_char
            curr.append(c)
        elif not in_string and not in_char:
            if c == '(':
                paren_depth += 1
                curr.append(c)
            elif c == ')':
                paren_depth = max(0, paren_depth - 1)
                curr.append(c)
            elif c == '[':
                bracket_depth += 1
                curr.append(c)
            elif c == ']':
                bracket_depth = max(0, bracket_depth - 1)
                curr.append(c)
            elif c == '{':
                brace_depth += 1
                curr.append(c)
            elif c == '}':
                brace_depth = max(0, brace_depth - 1)
                curr.append(c)
            elif c == ',' and paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
                args.append("".join(curr).strip())
                curr = []
            else:
                curr.append(c)
        else:
            curr.append(c)

    if curr:
        args.append("".join(curr).strip())

    return args


def extract_call_args(line_content: str, start_offset: int) -> Optional[Tuple[str, ...]]:
    """
    Extracts top-level arguments from a function call like `memset(dest, 0, sizeof(dest))`.
    `start_offset` must be the index of '(' in `line_content`.
    Returns a tuple of string arguments, or None if the parentheses are unbalanced or start_offset is invalid.
    """
    inner, _ = extract_balanced_parens(line_content, start_offset)
    if inner is None:
        return None
    return tuple(split_call_args(inner))



def extract_comments_from_raw_lines(raw_lines: List[str]) -> List[Tuple[int, str]]:
    """
    Extracts all line comments (// ...) and block comments (/* ... */)
    along with their starting 1-based line numbers.
    Strings and character literals are skipped so text inside literals
    is never mistaken for a comment.
    """
    source = "\n".join(raw_lines)
    comments: List[Tuple[int, str]] = []

    i = 0
    n = len(source)
    line_no = 1

    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False

    comment_start_line = 1
    comment_chars: List[str] = []

    while i < n:
        c = source[i]
        next_c = source[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if c == "\n":
                in_line_comment = False
                comments.append((comment_start_line, "".join(comment_chars)))
                comment_chars = []
                line_no += 1
            else:
                comment_chars.append(c)
            i += 1
            continue

        if in_block_comment:
            if c == "*" and next_c == "/":
                in_block_comment = False
                comment_chars.append("*/")
                comments.append((comment_start_line, "".join(comment_chars)))
                comment_chars = []
                i += 2
                continue
            else:
                if c == "\n":
                    line_no += 1
                comment_chars.append(c)
                i += 1
                continue

        if in_string:
            if c == "\n":
                line_no += 1
            elif c == "\\" and i + 1 < n:
                if source[i + 1] == "\n":
                    line_no += 1
                i += 2
                continue
            elif c == '"':
                in_string = False
            i += 1
            continue

        if in_char:
            if c == "\n":
                line_no += 1
            elif c == "\\" and i + 1 < n:
                if source[i + 1] == "\n":
                    line_no += 1
                i += 2
                continue
            elif c == "'":
                in_char = False
            i += 1
            continue

        if c == "/" and next_c == "/":
            in_line_comment = True
            comment_start_line = line_no
            comment_chars = ["//"]
            i += 2
            continue

        if c == "/" and next_c == "*":
            in_block_comment = True
            comment_start_line = line_no
            comment_chars = ["/*"]
            i += 2
            continue

        if c == '"':
            in_string = True
            i += 1
            continue

        if c == "'":
            in_char = True
            i += 1
            continue

        if c == "\n":
            line_no += 1

        i += 1

    if in_line_comment or in_block_comment:
        comments.append((comment_start_line, "".join(comment_chars)))

    return comments


class SuppressionMap:
    """
    Tracks which (line_number, rule_id) pairs should be suppressed based on
    `cgull-ignore` or `cgull-disable` directives found in comments in the source.

    Supports:
      // cgull-ignore                (suppress all rules on this line)
      // cgull-ignore: CGULL-001     (suppress specific rule(s) on this line)
      // cgull-disable-next-line CGULL-007 (suppress rule on NEXT line)
      /* cgull-disable-line CGULL-019 */
    """

    def __init__(self) -> None:
        # line_number -> set of rule_ids, or {"*"} for "suppress everything"
        self._same_line: Dict[int, Set[str]] = {}
        self._next_line: Dict[int, Set[str]] = {}

    @classmethod
    def from_source(cls, raw_lines: List[str]) -> "SuppressionMap":
        sup = cls()
        comment_spans = extract_comments_from_raw_lines(raw_lines)
        for line_no, comment_text in comment_spans:
            line_lower = comment_text.lower()
            if "cgull-ignore" not in line_lower and "cgull-disable" not in line_lower:
                continue
            for m in _SUPPRESS_RE.finditer(comment_text):
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


def compute_issue_fingerprint_tu(
    rule_id: str,
    original_file_path: str,
    *args: Any,
    **kwargs: Any,
) -> str:
    """
    Computes a stable TU-aware fingerprint retaining canonical origin path,
    rule ID, and normalized snippet semantics without hashing the line number
    to ensure stability under unrelated edits earlier in the file.

    Accepts both `(rule_id, canonical_path, code_snippet)` and legacy
    `(rule_id, canonical_path, original_line, code_snippet)`.
    """
    code_snippet = ""
    if "code_snippet" in kwargs:
        code_snippet = kwargs["code_snippet"]
    elif len(args) == 2:
        code_snippet = str(args[1])
    elif len(args) == 1:
        code_snippet = str(args[0])
    elif "snippet" in kwargs:
        code_snippet = kwargs["snippet"]

    return compute_issue_fingerprint(rule_id, original_file_path, code_snippet)


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
