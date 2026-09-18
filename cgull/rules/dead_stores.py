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


def _same_line_initializer_overwrites(ast_ctx) -> List[Tuple[object, object]]:
    """Return fallback bindings whose initializer is overwritten before any read.

    The regex extractor stores reads/writes at physical-line granularity. On a
    compact line such as ``int x = 0; x = 1;`` it therefore records the second
    occurrence of ``x`` as a declaration-line read and can hide the dead store.
    Recover only the unambiguous ordered case where the first post-declaration
    use is a plain assignment whose RHS does not read the same binding.
    """
    source_lines = (getattr(ast_ctx, "clean_source", "") or "\n".join(ast_ctx.source_lines)).splitlines()
    result = []
    for fn in getattr(ast_ctx, "functions", []):
        for c_var in _eligible_variables(fn):
            line_no = int(getattr(c_var, "declaration_line", 0) or 0)
            if not getattr(c_var, "has_initializer", False) or not (1 <= line_no <= len(source_lines)):
                continue

            line = mask_string_and_char_literals(source_lines[line_no - 1])
            name = re.escape(c_var.name)
            initializer = re.search(rf"\b{name}\b\s*=\s*.*?;", line)
            if initializer is None:
                continue

            tail = line[initializer.end():]
            first_use = re.search(rf"\b{name}\b", tail)
            if first_use is None:
                continue
            fragment = tail[first_use.start():]
            overwrite = re.match(rf"\b{name}\b\s*=(?!=)\s*([^;]*)", fragment)
            if overwrite is None:
                continue
            if re.search(rf"\b{name}\b", overwrite.group(1)):
                continue
            result.append((fn, c_var))
    return result


def _expanded_context(ast_ctx):
    """Use explicit expanded lexical coordinates without inverting a TU map."""
    context = copy(ast_ctx)
    context.functions = []
    for fn in ast_ctx.functions:
        expanded_fn = copy(fn)
        expanded_fn.start_line = fn.start_line_exp or fn.start_line
        expanded_fn.end_line = fn.end_line_exp or fn.end_line
        expanded_fn.variables = {}
        for variable in _raw_function_variables(fn):
            expanded = copy(variable)
            if variable.declaration_line_exp:
                expanded.declaration_line = variable.declaration_line_exp
                expanded.assigned_lines = variable.assigned_lines_exp
                expanded.read_lines = variable.read_lines_exp
            expanded_fn.variables[_variable_key(expanded)] = expanded
        context.functions.append(expanded_fn)
    return context


class DeadStoresRule(_BaseDeadStoresRule):
    """CGULL-042 with binding-preserving lexical fallback analysis."""

    def scan_ast(self, file_path, ast_ctx):
        if getattr(ast_ctx, "has_pycparser", False) and ast_ctx.pycparser_ast is not None:
            return super().scan_ast(file_path, ast_ctx)

        from ..models import FixType
        from .dead_store_initializers import (
            fallback_constant_identifiers,
            suppress_lexical_initializer,
        )
        from .fallback_writes import WriteSource, verified_write

        context = _expanded_context(ast_ctx)
        source = WriteSource(context)
        protected = _protected_loop_carried_writes(context)
        compact_overwrites = {
            (id(fn), _variable_key(variable))
            for fn, variable in _same_line_initializer_overwrites(context)
        }
        issues = []
        for fn in context.functions:
            constant_identifiers = fallback_constant_identifiers(context, fn)
            for variable in _eligible_variables(fn):
                writes = sorted(set(variable.assigned_lines))
                reads = variable.read_lines
                if (id(fn), _variable_key(variable)) in compact_overwrites:
                    reads = [line for line in reads if line != variable.declaration_line]
                for index, line in enumerate(writes):
                    next_line = writes[index + 1] if index + 1 < len(writes) else float("inf")
                    if any(line <= read < next_line for read in reads):
                        continue
                    if (_variable_key(variable), line) in protected:
                        continue
                    event = verified_write(context, fn, variable, line, source)
                    if event is None:
                        continue
                    if (
                        event.kind == "initializer"
                        and suppress_lexical_initializer(
                            context,
                            variable,
                            line,
                            constant_identifiers,
                        )
                    ):
                        continue
                    end_line = event.expanded_line + event.statement.count("\n")
                    issue = self.create_issue(
                        file_path=file_path,
                        line_number=event.expanded_line,
                        code_snippet="\n".join(context.source_lines[event.expanded_line - 1:end_line]).strip(),
                        message=f"Value assigned to local variable '{event.binding[0]}' in '{event.function}' is never read before reassignment or scope exit (dead store, CWE-563).",
                        column_number=event.column,
                        engine="AST",
                        fix_type=FixType.MANUAL_REVIEW,
                    )
                    issue.expanded_end_line = end_line
                    issues.append(issue)
        return issues
