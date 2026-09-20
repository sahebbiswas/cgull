"""Fallback control-flow refinements for CGULL-042 dead-store analysis.

Includes join-aware liveness for mutually exclusive if/else arms so a store
on one arm is not treated as killed by a sibling arm when a post-join read
consumes the value.
"""

from copy import copy
import re
from typing import Dict, List, Optional, Set, Tuple

from .misra_and_style import DeadStoresRule as _BaseDeadStoresRule
from ..utils import mask_string_and_char_literals


LoopInfo = Tuple[int, int, int, Set[str]]
VariableKey = Tuple[str, int, int]
ProtectedWrite = Tuple[VariableKey, int]
# (header_line, end_line, arms, inline_body_lines, cond_ranges)
# arms: inclusive body (start_line, end_line); braced interiors only.
# When body statements share the if-header line, that line is omitted from the
# arm span so condition side effects are not arm-local; inline_body_lines records
# those header lines for may-overwrite recovery. cond_ranges are (start, end)
# byte offsets of each if-condition "(...)".
IfChain = Tuple[
    int,
    int,
    Tuple[Tuple[int, int], ...],
    frozenset,
    Tuple[Tuple[int, int], ...],
]


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



def _is_ident_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def _skip_space(source: str, pos: int) -> int:
    """Advance past whitespace and C comments (`/* ... */`, `// ...`)."""
    n = len(source)
    while pos < n:
        if source[pos].isspace():
            pos += 1
            continue
        if source.startswith("//", pos):
            newline = source.find("\n", pos + 2)
            pos = n if newline < 0 else newline + 1
            continue
        if source.startswith("/*", pos):
            end = source.find("*/", pos + 2)
            if end < 0:
                return n
            pos = end + 2
            continue
        break
    return pos


def _skip_space_backward(source: str, pos: int) -> int:
    """Retreat to the last non-whitespace / non-comment index at or before *pos*."""
    while pos >= 0:
        if source[pos].isspace():
            pos -= 1
            continue
        if pos > 0 and source[pos - 1:pos + 1] == "*/":
            start = source.rfind("/*", 0, pos - 1)
            if start < 0:
                return pos
            pos = start - 1
            continue
        line_start = source.rfind("\n", 0, pos) + 1
        comment = source.find("//", line_start, pos + 1)
        if comment >= 0:
            pos = comment - 1
            continue
        break
    return pos


def _at_keyword(source: str, pos: int, keyword: str) -> bool:
    """True when *keyword* starts at *pos* with trailing identifier boundary."""
    end = pos + len(keyword)
    if not source.startswith(keyword, pos):
        return False
    if end < len(source) and _is_ident_char(source[end]):
        return False
    return True


def _body_span_positions(source: str, start: int) -> Optional[Tuple[int, int, int]]:
    """Return (body_start, body_end, pos_after) for a braced or single statement."""
    pos = _skip_space(source, start)
    if pos >= len(source) or source[pos] == ";":
        return None
    if source[pos] == "{":
        end = _matching_delimiter(source, pos, "{", "}")
        if end is None:
            return None
        return pos, end, end + 1
    end = _statement_end(source, pos)
    return pos, end, end + 1


def _preceded_by_else(masked: str, if_start: int) -> bool:
    """True when *if_start* is the `if` in an `else if` continuation."""
    pos = _skip_space_backward(masked, if_start - 1)
    if pos < 3 or masked[pos - 3:pos + 1] != "else":
        return False
    # Leading word boundary so identifiers like `some_else` / `belse` do not match.
    if pos >= 4 and _is_ident_char(masked[pos - 4]):
        return False
    return True


def _braced_arm_line_span(
    masked: str, body_start: int, body_end: int, header_line: int
) -> Tuple[Tuple[int, int], bool]:
    """Inclusive line span of statements inside `{...}`, excluding the braces.

    Condition-side effects on the `if (...) {` header line must not look like
    arm stores; otherwise a must-execute overwrite in the condition is treated
    as a may-overwrite and suppresses a true dead store (#530 vs #554).

    When the first interior statement shares *header_line*, that line is omitted
    from the returned span (column/span-aware exclusion of the condition). The
    second return value is True so callers can still treat same-line body stores
    as conditional may-overwrites.
    """
    inner = _skip_space(masked, body_start + 1)
    if inner >= body_end:
        # Empty `{ }` on the header line has no arm body stores.
        return (header_line + 1, header_line), False
    start_line = _line_number(masked, inner)
    end_pos = body_end - 1
    while end_pos > inner and masked[end_pos].isspace():
        end_pos -= 1
    end_line = _line_number(masked, end_pos)
    if start_line == header_line:
        # Body shares the condition line: drop the header from the line span so
        # condition assignments are not classified as exclusive-arm writes.
        return (header_line + 1, end_line), True
    return (start_line, end_line), False


def _arm_line_span(
    masked: str, body_start: int, body_end: int, header_line: int
) -> Tuple[Tuple[int, int], bool]:
    """Line span for one if/else arm body (braced interior or unbraced stmt)."""
    if masked[body_start] == "{":
        return _braced_arm_line_span(masked, body_start, body_end, header_line)
    start_line = _line_number(masked, body_start)
    end_line = _line_number(masked, body_end)
    if start_line == header_line:
        return (header_line + 1, end_line), True
    return (start_line, end_line), False


def _parse_if_chain(masked: str, if_keyword_start: int) -> Optional[IfChain]:
    """Parse one if / else-if / else chain into exclusive arm line spans."""
    arms: List[Tuple[int, int]] = []
    inline_body_lines: Set[int] = set()
    cond_ranges: List[Tuple[int, int]] = []
    header_line = _line_number(masked, if_keyword_start)
    pos = if_keyword_start

    while True:
        # Consume leading `if` (first arm or `else if`).
        if not _at_keyword(masked, pos, "if"):
            return None
        # Else-if headers use their own line for same-line body exclusion.
        arm_header_line = _line_number(masked, pos)
        pos = _skip_space(masked, pos + 2)
        if pos >= len(masked) or masked[pos] != "(":
            return None
        close = _matching_delimiter(masked, pos, "(", ")")
        if close is None:
            return None
        cond_ranges.append((pos, close))
        body = _body_span_positions(masked, close + 1)
        if body is None:
            return None
        body_start, body_end, pos = body
        span, inline = _arm_line_span(masked, body_start, body_end, arm_header_line)
        arms.append(span)
        if inline:
            inline_body_lines.add(arm_header_line)

        pos = _skip_space(masked, pos)
        if not _at_keyword(masked, pos, "else"):
            break
        pos = _skip_space(masked, pos + 4)
        if _at_keyword(masked, pos, "if"):
            continue
        # Final else arm.
        else_header_line = _line_number(masked, pos)
        body = _body_span_positions(masked, pos)
        if body is None:
            return None
        body_start, body_end, pos = body
        span, inline = _arm_line_span(masked, body_start, body_end, else_header_line)
        arms.append(span)
        if inline:
            inline_body_lines.add(else_header_line)
        break

    if not arms:
        return None
    # Empty (bumped) spans use start > end; still contribute header for end_line.
    spanned = [end for start, end in arms if start <= end]
    end_line = max(spanned + list(inline_body_lines) + [header_line])
    return header_line, end_line, tuple(arms), frozenset(inline_body_lines), tuple(cond_ranges)


def _mask_source_lines(source: str) -> str:
    return "\n".join(mask_string_and_char_literals(line) for line in source.split("\n"))


def _collect_if_else_chains(source: str) -> List[IfChain]:
    """Parse structured if/else-if/else chains once per translation unit."""
    masked = _mask_source_lines(source)
    chains: List[IfChain] = []
    for match in re.finditer(r"\bif\b", masked):
        if _preceded_by_else(masked, match.start()):
            continue
        parsed = _parse_if_chain(masked, match.start())
        if parsed is not None and len(parsed[2]) >= 1:
            chains.append(parsed)
    return chains


def _arm_index(line: int, chain: IfChain) -> Optional[int]:
    for index, (start, end) in enumerate(chain[2]):
        if start <= end and start <= line <= end:
            return index
    return None


def _condition_assigns_on_line(
    masked: str, cond_ranges: Tuple[Tuple[int, int], ...], name: str, line: int
) -> bool:
    """True when an if-condition covering *line* assigns *name* (must-execute)."""
    pattern = re.compile(rf"\b{re.escape(name)}\b\s*=(?!=)")
    for start, end in cond_ranges:
        if _line_number(masked, start) > line or _line_number(masked, end) < line:
            continue
        if pattern.search(masked[start : end + 1]):
            return True
    return False


def _are_exclusive_arm_lines(line1: int, line2: int, chains: List[IfChain]) -> bool:
    """True when the two lines sit on different arms of the same if/else chain."""
    for chain in chains:
        first = _arm_index(line1, chain)
        second = _arm_index(line2, chain)
        if first is not None and second is not None and first != second:
            return True
    return False


def _is_conditional_may_overwrite(
    earlier: int,
    later: int,
    chains: List[IfChain],
    *,
    name: str = "",
    masked: str = "",
) -> bool:
    """True when *later* is inside a branch that does not cover every path from *earlier*.

    A store on only some successors (if-without-else, or a nested if inside a
    shared arm) must not kill an earlier value when a join read remains reachable
    on another path.

    Same-line `if (x = 1) { ... }` bodies omit the header from arm spans; those
    lines are recovered via *inline_body_lines*. A condition assignment to *name*
    always executes and is therefore a must-overwrite, not a may-overwrite.
    """
    for chain in chains:
        header_line, _end_line, _arms, inline_body_lines, cond_ranges = chain
        later_arm = _arm_index(later, chain)
        inline_later = later in inline_body_lines
        if later_arm is None and not inline_later:
            continue
        if (
            name
            and masked
            and _condition_assigns_on_line(masked, cond_ranges, name, later)
        ):
            # Condition side effect must execute before either arm.
            continue
        earlier_arm = _arm_index(earlier, chain)
        if earlier_arm is not None:
            # Same chain: sibling exclusivity is handled separately; same-arm
            # sequential stores are must-overwrites for this chain.
            continue
        if earlier < header_line or (inline_later and earlier < later):
            return True
    return False


def _next_must_overwrite(
    write_line: int,
    writes: List[int],
    chains: List[IfChain],
    *,
    name: str = "",
    masked: str = "",
):
    """Earliest later write that kills *write_line* on every continuing path."""
    for later in writes:
        if later <= write_line:
            continue
        if _are_exclusive_arm_lines(write_line, later, chains):
            continue
        if _is_conditional_may_overwrite(
            write_line, later, chains, name=name, masked=masked
        ):
            continue
        return later
    return float("inf")


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

        body_span = _loop_body_span(masked, close + 1)
        if body_span is None:
            # This also excludes do/while tails: the token after ')' is ';'.
            continue
        header_line = _line_number(masked, match.start())
        # Keep loops even when the header has no identifier reads so body-carried
        # stores (e.g. walk-pointer updates) can still be protected.
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

            # Header reads plus in-body reads (via the back-edge) can consume a
            # carried store. Track names from the header, then also consider any
            # eligible binding with a read inside the loop span.
            carried_names = set(read_names)
            for c_var in variables:
                if c_var.declaration_line > header_line:
                    continue
                if any(header_line <= int(read) <= end_line for read in (c_var.read_lines or [])):
                    carried_names.add(c_var.name)

            for name in carried_names:
                candidates = []
                for c_var in variables:
                    if c_var.name != name or c_var.declaration_line > header_line:
                        continue
                    writes = sorted(set(getattr(c_var, "assigned_lines", []) or []))
                    loop_writes = [line for line in writes if start_line <= line <= end_line]
                    if not loop_writes:
                        continue
                    # Require evidence this binding is read in the loop; otherwise
                    # a write-only name from carried_names must not suppress dead stores.
                    header_hit = name in read_names
                    body_hit = any(header_line <= int(read) <= end_line for read in (c_var.read_lines or []))
                    if not (header_hit or body_hit):
                        continue
                    candidates.append((c_var, loop_writes))

                if not candidates:
                    continue

                # If more than one same-named binding has writes in the textual
                # body, the nearest declaration before the header is the binding
                # visible to the loop condition / body reads.
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
        src_text = getattr(context, "clean_source", "") or "\n".join(context.source_lines)
        masked_src = _mask_source_lines(src_text)
        if_chains = _collect_if_else_chains(src_text)
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
                for line in writes:
                    next_line = _next_must_overwrite(
                        line, writes, if_chains, name=variable.name, masked=masked_src
                    )
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