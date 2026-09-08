"""Fallback control-flow refinements for CGULL-042 dead-store analysis."""

from copy import copy
import re
from typing import Dict, List, Optional, Set, Tuple

from .misra_and_style import DeadStoresRule as _BaseDeadStoresRule
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


def _eligible_variables(fn):
    """Mirror the base rule's local-variable eligibility without collapsing scope."""
    param_names = {p.name for p in fn.parameters if p.name}
    result = []
    for c_var in _raw_function_variables(fn):
        name = getattr(c_var, "name", None)
        if not name or name in param_names or name.startswith("__"):
            continue
        if c_var.is_volatile or c_var.address_taken:
            continue
        result.append(c_var)
    return result


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
        variables = _eligible_variables(fn)
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


def _issue_signature(issue):
    """Stable signature used when supplementing base findings for shadowed bindings."""
    return (
        getattr(issue, "rule_id", None),
        getattr(issue, "line_number", None),
        getattr(issue, "message", None),
        getattr(issue, "code_snippet", None),
    )


def _write_bindings(ast_ctx) -> Dict[int, List[object]]:
    """Map each physical write line to the concrete eligible lexical bindings."""
    by_line: Dict[int, List[object]] = {}
    for fn in getattr(ast_ctx, "functions", []):
        for c_var in _eligible_variables(fn):
            for line_no in set(getattr(c_var, "assigned_lines", []) or []):
                by_line.setdefault(line_no, []).append(c_var)
    return by_line


def _shadowed_bindings(ast_ctx) -> List[Tuple[object, object]]:
    """Return ``(function, binding)`` pairs for names declared in multiple scopes."""
    shadowed = []
    for fn in getattr(ast_ctx, "functions", []):
        groups: Dict[str, List[object]] = {}
        for c_var in _eligible_variables(fn):
            groups.setdefault(c_var.name, []).append(c_var)
        for bindings in groups.values():
            if len(bindings) > 1:
                shadowed.extend((fn, c_var) for c_var in bindings)
    return shadowed


class DeadStoresRule(_BaseDeadStoresRule):
    """CGULL-042 with loop-aware precision for the lexical fallback tier."""

    def _base_scan_for_bindings(self, file_path, ast_ctx, fn_bindings):
        """Run the canonical base fallback once for a batch of concrete bindings."""
        scoped_ctx = copy(ast_ctx)
        scoped_functions = []
        for fn, c_var in fn_bindings:
            scoped_fn = copy(fn)
            scoped_fn.variables = {c_var.name: c_var}
            scoped_functions.append(scoped_fn)
        scoped_ctx.functions = scoped_functions
        scoped_ctx.has_pycparser = False
        scoped_ctx.pycparser_ast = None
        return super().scan_ast(file_path, scoped_ctx)

    def _base_scan_for_binding(self, file_path, ast_ctx, fn, c_var):
        """Rare collision fallback for bindings sharing one physical write line."""
        return self._base_scan_for_bindings(file_path, ast_ctx, [(fn, c_var)])

    def scan_ast(self, file_path, ast_ctx):
        if getattr(ast_ctx, "has_pycparser", False) and ast_ctx.pycparser_ast is not None:
            return super().scan_ast(file_path, ast_ctx)

        protected = _protected_loop_carried_writes(ast_ctx)
        write_bindings = _write_bindings(ast_ctx)
        shadowed_pairs = _shadowed_bindings(ast_ctx)
        shadowed_keys = {_variable_key(c_var) for _fn, c_var in shadowed_pairs}

        # Start from the canonical base result, but identify findings structurally
        # by their write line and CVariable binding instead of parsing issue prose.
        # Findings for shadowed bindings are replaced by the scoped batch below.
        issues = []
        ambiguous_lines = set()
        for issue in super().scan_ast(file_path, ast_ctx):
            line_no = getattr(issue, "line_number", None)
            candidates = write_bindings.get(line_no, [])
            if len(candidates) == 1:
                key = _variable_key(candidates[0])
                if key in shadowed_keys or (key, line_no) in protected:
                    continue
                issues.append(issue)
            elif len(candidates) > 1:
                # A compact source line may contain writes to multiple bindings.
                # Re-evaluate those bindings explicitly below rather than guessing
                # identity from the issue's human-readable message.
                ambiguous_lines.add(line_no)
            else:
                issues.append(issue)

        # Most shadowed bindings have distinct write lines. Analyze all of them in
        # one base-rule invocation, avoiding the former N full fallback scans. Only
        # bindings that share a physical write line take the rare individual path.
        collision_keys = {
            _variable_key(c_var)
            for line_no in ambiguous_lines
            for c_var in write_bindings.get(line_no, [])
        }
        batch_pairs = [
            (fn, c_var)
            for fn, c_var in shadowed_pairs
            if _variable_key(c_var) not in collision_keys
        ]
        batch_line_binding = {}
        for _fn, c_var in batch_pairs:
            for line_no in set(getattr(c_var, "assigned_lines", []) or []):
                batch_line_binding[line_no] = c_var

        existing = {_issue_signature(issue) for issue in issues}
        if batch_pairs:
            for issue in self._base_scan_for_bindings(file_path, ast_ctx, batch_pairs):
                line_no = getattr(issue, "line_number", None)
                c_var = batch_line_binding.get(line_no)
                if c_var is None or (_variable_key(c_var), line_no) in protected:
                    continue
                signature = _issue_signature(issue)
                if signature not in existing:
                    issues.append(issue)
                    existing.add(signature)

        # Same-line writes are intentionally uncommon; preserve exact identity by
        # evaluating only those colliding bindings individually.
        collision_pairs = []
        seen_collision_keys = set()
        for fn in getattr(ast_ctx, "functions", []):
            for c_var in _eligible_variables(fn):
                key = _variable_key(c_var)
                if key in collision_keys and key not in seen_collision_keys:
                    collision_pairs.append((fn, c_var))
                    seen_collision_keys.add(key)

        for fn, c_var in collision_pairs:
            key = _variable_key(c_var)
            for issue in self._base_scan_for_binding(file_path, ast_ctx, fn, c_var):
                line_no = getattr(issue, "line_number", None)
                if (key, line_no) in protected:
                    continue
                signature = _issue_signature(issue)
                if signature not in existing:
                    issues.append(issue)
                    existing.add(signature)

        return issues
