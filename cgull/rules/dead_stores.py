"""Fallback control-flow refinements for CGULL-042 dead-store analysis."""

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .misra_and_style import DeadStoresRule as _BaseDeadStoresRule
from ..utils import mask_string_and_char_literals


_IDENTIFIER = r"[A-Za-z_]\w*"


def _matching_delimiter(source: str, start: int, opener: str, closer: str) -> Optional[int]:
    """Return the matching delimiter position for *start*, or None if unbalanced."""
    depth = 0
    for pos in range(start, len(source)):
        char = source[pos]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return pos
    return None


def _line_number(source: str, pos: int) -> int:
    return source.count("\n", 0, pos) + 1


def _split_for_clauses(header: str) -> List[str]:
    """Split a for-header into init/condition/iteration at top-level semicolons."""
    clauses: List[str] = []
    start = 0
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    for pos, char in enumerate(header):
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
        elif char == ";" and paren_depth == bracket_depth == brace_depth == 0:
            clauses.append(header[start:pos])
            start = pos + 1
    clauses.append(header[start:])
    return clauses


def _statement_end(source: str, start: int) -> int:
    """Best-effort end position for an unbraced loop body."""
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    for pos in range(start, len(source)):
        char = source[pos]
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            if brace_depth == 0:
                return pos
            brace_depth -= 1
        elif char == ";" and paren_depth == bracket_depth == brace_depth == 0:
            return pos
    return len(source) - 1


def _loop_body_span(source: str, start: int) -> Optional[Tuple[int, int]]:
    pos = start
    while pos < len(source) and source[pos].isspace():
        pos += 1
    if pos >= len(source) or source[pos] == ";":
        return None
    if source[pos] == "{":
        end = _matching_delimiter(source, pos, "{", "}")
        if end is None:
            return None
    else:
        end = _statement_end(source, pos)
    return _line_number(source, pos), _line_number(source, end)


def _loop_carried_read_spans(source: str, variable: str) -> List[Tuple[int, int]]:
    """Return loop-body line spans whose next-iteration expressions read *variable*.

    Only while conditions and the condition/iteration clauses of for loops are
    considered.  A for-loop initializer is intentionally excluded because it
    executes only once and therefore cannot consume a body write on a back-edge.
    do/while needs no special handling: its condition is textually after the body,
    so the existing fallback line-order check already observes that read.
    """
    masked = "\n".join(mask_string_and_char_literals(line) for line in source.split("\n"))
    variable_re = re.compile(rf"\b{re.escape(variable)}\b")
    spans: List[Tuple[int, int]] = []

    for match in re.finditer(r"\b(while|for)\b", masked):
        keyword = match.group(1)
        pos = match.end()
        while pos < len(masked) and masked[pos].isspace():
            pos += 1
        if pos >= len(masked) or masked[pos] != "(":
            continue
        close = _matching_delimiter(masked, pos, "(", ")")
        if close is None:
            continue

        header = masked[pos + 1:close]
        if keyword == "for":
            clauses = _split_for_clauses(header)
            if len(clauses) != 3:
                continue
            carried_expression = clauses[1] + "\n" + clauses[2]
        else:
            carried_expression = header

        if not variable_re.search(carried_expression):
            continue

        body_span = _loop_body_span(masked, close + 1)
        if body_span is not None:
            spans.append(body_span)

    return spans


def _protected_loop_carried_writes(ast_ctx) -> Set[Tuple[int, str]]:
    """Find fallback writes that are consumed on a structured-loop back-edge.

    A write is protected only when it is the final textual write to that variable
    in the enclosing loop body.  This preserves genuine dead-store reports such
    as ``X = 1; X = 2;`` inside ``while (X)``: only the second value can reach the
    next condition evaluation.
    """
    protected: Set[Tuple[int, str]] = set()
    source = getattr(ast_ctx, "clean_source", "") or "\n".join(ast_ctx.source_lines)

    for fn in getattr(ast_ctx, "functions", []):
        param_names = {p.name for p in fn.parameters if p.name}
        variables: Dict[str, object] = {}
        for c_var in fn.variables.values():
            name = getattr(c_var, "name", None)
            if not name or name in param_names or name.startswith("__"):
                continue
            variables[name] = c_var

        for name, c_var in variables.items():
            writes = sorted(set(getattr(c_var, "assigned_lines", []) or []))
            if not writes:
                continue
            for start_line, end_line in _loop_carried_read_spans(source, name):
                loop_writes = [line for line in writes if start_line <= line <= end_line]
                if loop_writes:
                    protected.add((loop_writes[-1], name))

    return protected


class DeadStoresRule(_BaseDeadStoresRule):
    """CGULL-042 with loop-aware precision for the lexical fallback tier."""

    def scan_ast(self, file_path, ast_ctx):
        issues = super().scan_ast(file_path, ast_ctx)
        if getattr(ast_ctx, "has_pycparser", False) and ast_ctx.pycparser_ast is not None:
            return issues

        protected = _protected_loop_carried_writes(ast_ctx)
        if not protected:
            return issues

        filtered = []
        for issue in issues:
            line_number = getattr(issue, "line_number", None)
            message = getattr(issue, "message", "")
            variable_match = re.search(r"local variable '([^']+)'", message)
            if variable_match and (line_number, variable_match.group(1)) in protected:
                continue
            filtered.append(issue)
        return filtered
