"""Fallback control-flow refinements for CGULL-042 dead-store analysis."""

import re
from typing import List, Optional, Set, Tuple

from .misra_and_style import DeadStoresRule as _BaseDeadStoresRule
from ..models import FixType
from ..utils import mask_string_and_char_literals


LoopInfo = Tuple[int, int, int, Set[str]]
VariableKey = Tuple[str, int, int]
ProtectedWrite = Tuple[VariableKey, int]


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


def _collect_loop_infos(source: str) -> List[LoopInfo]:
    """Parse loop headers once and retain their back-edge reads and body spans."""
    masked = "\n".join(mask_string_and_char_literals(line) for line in source.split("\n"))
    loops: List[LoopInfo] = []

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
            # The initializer executes only once; only condition/iteration can
            # consume a body write on the next iteration.
            carried_expression = clauses[1] + "\n" + clauses[2]
        else:
            carried_expression = header

        read_names = set(re.findall(r"\b[A-Za-z_]\w*\b", carried_expression))
        if not read_names:
            continue

        body_span = _loop_body_span(masked, close + 1)
        if body_span is None:
            # This also excludes do/while tails: the token after ')' is ';'.
            continue
        header_line = _line_number(masked, match.start())
        loops.append((header_line, body_span[0], body_span[1], read_names))

    return loops


def _variable_key(c_var) -> VariableKey:
    """Stable identity for one lexical local binding."""
    return (
        getattr(c_var, "name", ""),
        int(getattr(c_var, "enclosing_block_id", 0) or 0),
        int(getattr(c_var, "declaration_line", 0) or 0),
    )


def _raw_function_variables(fn):
    """Return every lexical binding, including same-named shadowed locals."""
    if isinstance(fn.variables, dict):
        return list(dict.values(fn.variables))
    return list(fn.variables)


def _protected_loop_carried_writes(ast_ctx) -> Set[ProtectedWrite]:
    """Find fallback writes consumed by the next structured-loop iteration.

    Loop structure is parsed once per translation unit. Protection is associated
    with the concrete lexical variable binding rather than only its name. When
    same-named bindings exist, only a declaration visible before the loop header
    can satisfy that header read; body-local shadows therefore cannot inherit the
    outer variable's protection.
    """
    protected: Set[ProtectedWrite] = set()
    source = getattr(ast_ctx, "clean_source", "") or "\n".join(ast_ctx.source_lines)
    loops = _collect_loop_infos(source)

    for fn in getattr(ast_ctx, "functions", []):
        param_names = {p.name for p in fn.parameters if p.name}
        variables = [
            c_var
            for c_var in _raw_function_variables(fn)
            if getattr(c_var, "name", None)
            and c_var.name not in param_names
            and not c_var.name.startswith("__")
        ]

        fn_start = int(getattr(fn, "start_line", 0) or 0)
        fn_end = int(getattr(fn, "end_line", 0) or 0)
        for header_line, start_line, end_line, read_names in loops:
            if fn_start and header_line < fn_start:
                continue
            if fn_end and header_line > fn_end:
                continue

            for name in read_names:
                candidates = []
                for c_var in variables:
                    if c_var.name != name or c_var.declaration_line > header_line:
                        continue
                    writes = sorted(set(getattr(c_var, "assigned_lines", []) or []))
                    loop_writes = [line for line in writes if start_line <= line <= end_line]
                    if loop_writes:
                        candidates.append((c_var, loop_writes))

                if not candidates:
                    continue

                # If more than one same-named binding has writes in the textual
                # body, the nearest declaration before the header is the binding
                # visible to the loop condition.
                c_var, loop_writes = max(
                    candidates,
                    key=lambda item: item[0].declaration_line,
                )
                protected.add((_variable_key(c_var), loop_writes[-1]))

    return protected


class DeadStoresRule(_BaseDeadStoresRule):
    """CGULL-042 with loop-aware precision for the lexical fallback tier."""

    def _fallback_issue(self, file_path, ast_ctx, fn, c_var, line_no):
        name = c_var.name
        snippet = (
            ast_ctx.source_lines[line_no - 1].strip()
            if 1 <= line_no <= len(ast_ctx.source_lines)
            else f"{name} = ...;"
        )
        return self.create_issue(
            file_path=file_path,
            line_number=line_no,
            code_snippet=snippet,
            message=(
                f"Value assigned to local variable '{name}' in '{fn.name}' is never read "
                "before reassignment or scope exit (dead store, CWE-563)."
            ),
            column_number=1,
            engine="AST",
            fix_type=FixType.SAFE_FIX if snippet.endswith(";") else FixType.MANUAL_REVIEW,
        )

    def _scan_fallback(self, file_path, ast_ctx):
        issues = []
        protected = _protected_loop_carried_writes(ast_ctx)

        for fn in ast_ctx.functions:
            param_names = {p.name for p in fn.parameters if p.name}
            for c_var in _raw_function_variables(fn):
                name = getattr(c_var, "name", None)
                if not name or name in param_names or name.startswith("__"):
                    continue
                if c_var.is_volatile or c_var.address_taken:
                    continue

                key = _variable_key(c_var)
                writes = sorted(set(getattr(c_var, "assigned_lines", []) or []))
                reads = sorted(set(getattr(c_var, "read_lines", []) or []))
                if not writes:
                    continue

                if not reads:
                    for line_no in writes:
                        if (key, line_no) not in protected:
                            issues.append(self._fallback_issue(file_path, ast_ctx, fn, c_var, line_no))
                    continue

                for index, line_no in enumerate(writes):
                    next_write = writes[index + 1] if index + 1 < len(writes) else float("inf")
                    has_read = any(line_no <= read_line < next_write for read_line in reads)
                    if not has_read and (key, line_no) not in protected:
                        issues.append(self._fallback_issue(file_path, ast_ctx, fn, c_var, line_no))

        return issues

    def scan_ast(self, file_path, ast_ctx):
        if getattr(ast_ctx, "has_pycparser", False) and ast_ctx.pycparser_ast is not None:
            return super().scan_ast(file_path, ast_ctx)
        return self._scan_fallback(file_path, ast_ctx)
