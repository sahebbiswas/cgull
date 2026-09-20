"""Data-flow buffer overflow detection for classic string and format APIs."""

import ast
import re
from collections import deque
from typing import List, Optional, Set, Tuple

from pycparser import c_ast

from ...ast_analyzer import CASTContext, _format_pycparser_expr
from ...cfg import TERMINATING_CALL_NAMES, build_cfg, find_function_def
from ...models import AnalysisEngine, FixType, Issue, RuleCategory, Severity
from .helpers import _source_snippet
from .memcpy_struct_member_overflow import MemcpyStructMemberOverflowRule


class BufferCopyOverflowRule(MemcpyStructMemberOverflowRule):
    """Detect string/format writes whose required extent cannot be proven to fit."""

    rule_id = "CGULL-048"
    name = "Data-Flow Buffer Copy Overflow"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = (
        "Detect classic string copy, concatenation, format, and input calls where destination "
        "capacity is known but the resulting write extent cannot be proven to fit."
    )
    implementation_method = "AST destination-capacity and source-extent reasoning"
    implementation_complexity = "High"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-121 / CWE-122 / CWE-120"
    remediation_suggestion = (
        "Use a bounded API and prove the copied/formatted extent is smaller than the destination "
        "capacity on every path (including space for the terminating NUL)."
    )
    sample_vulnerable_code = (
        "void copy(char *src) {\n"
        "    char dst[16];\n"
        "    strcpy(dst, src); // source extent is not bounded by sizeof(dst)\n"
        "}"
    )
    sample_remediated_code = (
        "void copy(char *src) {\n"
        "    char dst[16];\n"
        "    snprintf(dst, sizeof(dst), \"%s\", src);\n"
        "}"
    )
    analysis_engine = AnalysisEngine.HYBRID

    # memcpy/memmove remain owned by CGULL-044. Keeping the rule families
    # disjoint prevents duplicate findings while still reusing CGULL-044's
    # destination-capacity resolver through inheritance.
    TARGET_FUNCS = {"strcpy", "strcat", "sprintf", "gets", "scanf"}

    @staticmethod
    def _literal_string_length(expr: str) -> Optional[int]:
        """Return the C string payload length, excluding the trailing NUL."""
        text = expr.strip()
        if not re.fullmatch(r'(?:u8|u|U|L)?"(?:\\.|[^"\\])*"', text):
            return None
        text = re.sub(r'^(?:u8|u|U|L)', '', text)
        try:
            value = ast.literal_eval(text)
        except (SyntaxError, ValueError):
            return None
        return len(value) if isinstance(value, str) else None

    def _string_source_extent(
        self,
        source_expr: str,
        fn,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Optional[int]:
        """Return a conservative byte upper bound including the terminating NUL."""
        literal_len = self._literal_string_length(source_expr)
        if literal_len is not None:
            return literal_len + 1
        return self._resolve_dest_capacity(source_expr, fn, line_no, ast_ctx)

    def _known_dest_string_length(
        self,
        dest_expr: str,
        fn,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Optional[int]:
        """Recover simple local string initializers/assignments before strcat()."""
        name = dest_expr.strip()
        if not re.fullmatch(r'[A-Za-z_]\w*', name):
            return None
        lines = ast_ctx.source_lines
        start = max(1, getattr(fn, "start_line", 1))
        known: Optional[int] = None
        for physical in range(start, min(line_no, len(lines) + 1)):
            text = lines[physical - 1]
            decl = re.search(
                rf'\b{re.escape(name)}\s*\[[^\]]*\]\s*=\s*((?:u8|u|U|L)?"(?:\\.|[^"\\])*")',
                text,
            )
            assign = re.search(
                rf'\b{re.escape(name)}\s*=\s*((?:u8|u|U|L)?"(?:\\.|[^"\\])*")',
                text,
            )
            copy = re.search(
                rf'\bstrcpy\s*\(\s*{re.escape(name)}\s*,\s*((?:u8|u|U|L)?"(?:\\.|[^"\\])*")\s*\)',
                text,
            )
            empty = re.search(rf'\b{re.escape(name)}\s*\[\s*0\s*\]\s*=\s*[\'\"]\\0[\'\"]', text)
            match = decl or assign or copy
            if match:
                known = self._literal_string_length(match.group(1))
            elif empty:
                known = 0
            elif known is not None and re.search(
                rf'\b(?:strcat|sprintf|gets|scanf)\s*\([^;]*\b{re.escape(name)}\b', text
            ):
                known = None
        return known

    @staticmethod
    def _scanf_string_destinations(
        format_expr: str,
        args: List[str],
    ) -> List[Tuple[str, Optional[int], str]]:
        """Return (destination, width, conversion) for scanf %s and scansets."""
        if not re.fullmatch(r'(?:u8|u|U|L)?"(?:\\.|[^"\\])*"', format_expr.strip()):
            return []
        try:
            fmt = ast.literal_eval(re.sub(r'^(?:u8|u|U|L)', '', format_expr.strip()))
        except (SyntaxError, ValueError):
            return []

        # Consume exactly one scanset conversion at a time. C permits an
        # optional '^' followed by an optional leading ']' literal; after
        # that, the first ']' terminates the scanset.
        conversion_re = re.compile(
            r'%(?!%)(\*)?(\d+)?(?:hh|h|ll|l|j|z|t|L)?'
            r'(\[\^?\]?[^\]]*\]|[A-Za-z])'
        )
        result: List[Tuple[str, Optional[int], str]] = []
        arg_index = 0
        for match in conversion_re.finditer(fmt):
            suppress, width, conversion = match.groups()
            if suppress:
                continue
            if arg_index >= len(args):
                break
            if conversion == "s" or conversion.startswith("["):
                result.append(
                    (args[arg_index], int(width) if width else None, conversion)
                )
            arg_index += 1
        return result

    # Local inspect/rewrite callees that read or rewrite the temporary buffer
    # without escaping its contents to a caller-visible sink.
    _BUFFER_LOCAL_INSPECT = frozenset({
        "sprintf",
        "snprintf",
        "vsprintf",
        "vsnprintf",
        "sscanf",
        "scanf",
        "fscanf",
        "vsscanf",
        "strlen",
        "strnlen",
        "strcmp",
        "strncmp",
        "memcmp",
        "memchr",
        "strchr",
        "strrchr",
        "strstr",
        "atoi",
        "atol",
        "atoll",
        "strtod",
        "strtof",
        "strtol",
        "strtoll",
        "strtoul",
        "strtoull",
    })
    # Process-terminating calls only (aligned with CFG TERMINATING_CALL_NAMES).
    # longjmp/siglongjmp are not bails: they can resume a handler that still
    # uses the buffer. pthread_exit is extra beyond the CFG terminator set.
    _BAIL_CALLEES = frozenset(TERMINATING_CALL_NAMES) | frozenset({"pthread_exit"})
    _FORMATTER_WRITE_DEST = frozenset({
        "sprintf",
        "snprintf",
        "vsprintf",
        "vsnprintf",
    })
    _SCANNER_INPUT_FIRST = frozenset({
        "sscanf",
        "vsscanf",
    })

    @staticmethod
    def _dest_base_name(dest_expr: str) -> Optional[str]:
        """Strip casts/address-of noise and return a plain destination identifier."""
        dest_clean = dest_expr.strip()
        dest_clean = re.sub(
            r'^\s*\(\s*(?:const\s+)?(?:char|int8_t|uint8_t|void|unsigned\s+char|signed\s+char|int)\s*\*+\s*\)\s*',
            '',
            dest_clean,
        ).strip()
        while dest_clean.startswith('(') and dest_clean.endswith(')'):
            dest_clean = dest_clean[1:-1].strip()
        if dest_clean.startswith('&'):
            dest_clean = dest_clean[1:].strip()
        m_idx = re.match(r'^([A-Za-z_]\w*)\s*\[\s*\d+\s*\]$', dest_clean)
        if m_idx:
            dest_clean = m_idx.group(1)
        if re.fullmatch(r'[A-Za-z_]\w*', dest_clean):
            return dest_clean
        return None

    @staticmethod
    def _strip_ast_casts(node):
        while isinstance(node, c_ast.Cast):
            node = node.expr
        return node

    @classmethod
    def _is_int_constant(cls, node, value: int) -> bool:
        node = cls._strip_ast_casts(node)
        if isinstance(node, c_ast.Constant) and node.type in {"int", "unsigned int", "long"}:
            token = re.sub(r'[uUlL]+$', '', str(node.value))
            try:
                return int(token, 0) == value
            except ValueError:
                return False
        if isinstance(node, c_ast.UnaryOp) and node.op == '+' and cls._is_int_constant(node.expr, value):
            return True
        if isinstance(node, c_ast.UnaryOp) and node.op == '-' and cls._is_int_constant(node.expr, -value):
            return True
        return False

    @classmethod
    def _is_length_ref(cls, node, length_var: str) -> bool:
        node = cls._strip_ast_casts(node)
        return isinstance(node, c_ast.ID) and node.name == length_var

    @classmethod
    def _is_sizeof_dest(cls, node, dest_name: str) -> bool:
        node = cls._strip_ast_casts(node)
        if not (isinstance(node, c_ast.UnaryOp) and node.op == 'sizeof'):
            return False
        inner = cls._strip_ast_casts(node.expr)
        if isinstance(inner, c_ast.ID) and inner.name == dest_name:
            return True
        # sizeof(dest) may appear as a parenthesized identifier expression.
        if isinstance(inner, c_ast.Typename):
            return False
        return False

    @classmethod
    def _is_sizeof_dest_minus_one(cls, node, dest_name: str) -> bool:
        node = cls._strip_ast_casts(node)
        if isinstance(node, c_ast.BinaryOp) and node.op == '-':
            return cls._is_sizeof_dest(node.left, dest_name) and cls._is_int_constant(node.right, 1)
        return False

    @classmethod
    def _is_capacity_overflow_compare(cls, node, length_var: str, dest_name: str) -> bool:
        """True for length-vs-capacity compares that reject an overflowing sprintf result."""
        if not isinstance(node, c_ast.BinaryOp):
            return False
        op = node.op
        left, right = node.left, node.right

        def length_side(side):
            return cls._is_length_ref(side, length_var)

        def capacity_ge(side):
            # length >= sizeof(dest)
            return cls._is_sizeof_dest(side, dest_name)

        def capacity_gt_minus_one(side):
            # length > sizeof(dest) - 1
            return cls._is_sizeof_dest_minus_one(side, dest_name)

        # length >= sizeof(dest)  /  length > sizeof(dest) - 1
        # Note: length > sizeof(dest) is NOT sufficient — length == sizeof(dest)
        # still overflows by the terminating NUL.
        if length_side(left):
            if op == '>=' and capacity_ge(right):
                return True
            if op == '>' and capacity_gt_minus_one(right):
                return True
        # sizeof(dest) <= length  /  sizeof(dest) - 1 < length
        if length_side(right):
            if op == '<=' and capacity_ge(left):
                return True
            if op == '<' and capacity_gt_minus_one(left):
                return True
        return False

    @classmethod
    def _or_clauses(cls, node):
        if isinstance(node, c_ast.BinaryOp) and node.op == '||':
            return cls._or_clauses(node.left) + cls._or_clauses(node.right)
        return [node]

    @classmethod
    def _is_length_capacity_reject_cond(cls, cond, length_var: str, dest_name: str) -> bool:
        if cond is None:
            return False
        return any(
            cls._is_capacity_overflow_compare(part, length_var, dest_name)
            for part in cls._or_clauses(cond)
        )

    def _arg_mentions_dest(self, arg_expr: str, dest_name: str) -> bool:
        if not dest_name:
            return False
        cleaned = self._dest_base_name(arg_expr) or arg_expr.strip()
        if cleaned == dest_name:
            return True
        return bool(re.search(rf'\b{re.escape(dest_name)}\b', arg_expr))

    def _scanner_string_outputs_stay_local(
        self, format_expr: str, output_args, dest_name: str
    ) -> bool:
        """True when every %s/%[ output of a scan stays in ``dest`` (or none exist)."""
        for out, _width, _conversion in self._scanf_string_destinations(
            format_expr, list(output_args)
        ):
            if not self._arg_mentions_dest(out, dest_name):
                return False
        return True

    def _call_is_local_buffer_inspect(self, call, dest_name: str) -> bool:
        """True when call only inspects or rewrites dest in place (no escape).

        Formatters in ``_BUFFER_LOCAL_INSPECT`` are local only when ``dest`` is the
        write target and does not also appear as a source argument. Passing the
        defended buffer as a source into another destination (e.g.
        ``sprintf(out, "%s", number_buffer)``) or self-copying through a
        formatter (``sprintf(buf, "%s", buf)``) is an escape.

        Scan family calls are classified by argument role: ``sscanf(buf, "%s",
        out)`` escapes when the defended buffer is the input and a string
        conversion writes to an external destination; numeric parses into locals
        (cJSON ``sscanf(..., "%lg", &test)``) remain local.
        """
        callee = call.direct_callee or ''
        if callee not in self._BUFFER_LOCAL_INSPECT:
            return False
        args = call.actual_arguments or ()
        if callee in self._FORMATTER_WRITE_DEST:
            if args and self._dest_base_name(args[0]) == dest_name:
                # Dest is write target; any later mention is a self-copy escape.
                return not any(
                    self._arg_mentions_dest(arg, dest_name) for arg in args[1:]
                )
            # Source use feeding a different write target is not local.
            return not any(self._arg_mentions_dest(arg, dest_name) for arg in args)
        if callee in self._SCANNER_INPUT_FIRST:
            if not args:
                return True
            # Buffer used as the scan input string.
            if self._arg_mentions_dest(args[0], dest_name):
                if len(args) < 2:
                    return True
                return self._scanner_string_outputs_stay_local(
                    args[1], args[2:], dest_name
                )
            # Buffer only as an output destination: in-place rewrite.
            return True
        return True

    def _event_escapes_buffer(self, event, dest_name: str) -> bool:
        """True when event sends dest contents to a non-local sink."""
        if event.kind == 'return':
            expr = (event.expr_str or '')
            return bool(re.search(rf'\b{re.escape(dest_name)}\b', expr))

        # Simple aliases (``char *p = number_buffer`` / ``p = number_buffer``)
        # let later uses omit ``dest_name``; treat the aliasing itself as escape.
        alias_writes = getattr(event, 'alias_writes', None) or {}
        if any(rhs == dest_name for rhs in alias_writes.values()):
            return True

        for call in getattr(event, 'calls', ()) or ():
            callee = call.direct_callee or ''
            if callee in self._BAIL_CALLEES:
                continue
            if self._call_is_local_buffer_inspect(call, dest_name):
                continue
            for arg in call.actual_arguments:
                if self._arg_mentions_dest(arg, dest_name):
                    return True
        return False

    def _branch_only_bails(self, cfg, start_id: int, dest_name: str) -> bool:
        """Overflow branch must exit without escaping the buffer.

        Only unconditional ``return`` and process-terminating calls count as
        bails. Resolved ``goto`` targets are followed; unresolved/unknown
        control flow and ``longjmp`` are treated conservatively (not bails).
        """
        if start_id not in cfg.nodes:
            return False
        seen: Set[int] = set()
        stack = [start_id]
        reached_exit = False
        while stack:
            nid = stack.pop()
            if nid in seen:
                continue
            seen.add(nid)
            node = cfg.nodes[nid]
            if (
                node.kind == 'unknown_control_flow'
                or getattr(node, 'is_unknown_control_flow', False)
            ):
                return False
            if self._event_escapes_buffer(node, dest_name):
                return False
            if node.kind == 'return':
                reached_exit = True
                continue
            terminated = False
            for call in getattr(node, 'calls', ()) or ():
                if (call.direct_callee or '') in self._BAIL_CALLEES:
                    reached_exit = True
                    terminated = True
                    break
            if terminated:
                continue
            # Follow resolved goto / ordinary successors; do not treat goto as bail.
            if not node.successors:
                return False
            for succ in node.successors:
                stack.append(succ)
        return reached_exit

    def _reject_safe_successor(self, cfg, cond_id: int, dest_name: str, length_var: str) -> Optional[int]:
        """Return the safe (non-overflow) successor id for a length-vs-capacity reject."""
        node = cfg.nodes.get(cond_id)
        if node is None or node.kind != 'if_cond' or len(node.successors) < 1:
            return None
        ast_node = getattr(node, '_ast_node', None)
        cond = getattr(ast_node, 'cond', None) if ast_node is not None else None
        if not self._is_length_capacity_reject_cond(cond, length_var, dest_name):
            return None
        true_succ = node.successors[0]
        if not self._branch_only_bails(cfg, true_succ, dest_name):
            return None
        if len(node.successors) > 1:
            return node.successors[1]
        # No else: safe path is whatever follows; treat as no explicit safe edge id
        # by returning a sentinel that means "any non-true successor path".
        return -1

    def _has_post_sprintf_length_defense(
        self,
        funcdef,
        ast_ctx: CASTContext,
        dest_expr: str,
        line_no: int,
    ) -> bool:
        """Credit fail-closed length-vs-capacity checks after sprintf into a fixed buffer.

        Suppress CGULL-048 when the sprintf return value is captured and every
        path from that write to an external use of the destination passes through
        a length-vs-``sizeof(dest)`` reject that bails out (cJSON ``print_number``).
        """
        dest_name = self._dest_base_name(dest_expr)
        if not dest_name or funcdef is None:
            return False

        cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, 'line_map', None))
        if cfg is None or cfg.entry is None:
            return False

        write_ids: List[Tuple[int, str]] = []
        for nid, event in cfg.nodes.items():
            for call in getattr(event, 'calls', ()) or ():
                if call.direct_callee != 'sprintf':
                    continue
                if not call.actual_arguments:
                    continue
                if self._dest_base_name(call.actual_arguments[0]) != dest_name:
                    continue
                loc = call.source_location
                call_line = loc.line_number if loc is not None else event.line_number
                if call_line != line_no:
                    continue
                length_var = call.result_target
                if not length_var:
                    return False
                write_ids.append((nid, length_var))
        if not write_ids:
            return False

        for write_id, length_var in write_ids:
            reject_safe = {}
            for nid in cfg.nodes:
                safe = self._reject_safe_successor(cfg, nid, dest_name, length_var)
                if safe is not None:
                    reject_safe[nid] = safe

            if not reject_safe:
                return False

            # BFS: state is (node_id, passed_safe_reject).
            visited: Set[Tuple[int, bool]] = set()
            queue = deque([(write_id, False)])
            saw_reject = False
            while queue:
                nid, passed = queue.popleft()
                state = (nid, passed)
                if state in visited:
                    continue
                visited.add(state)
                node = cfg.nodes[nid]

                if nid != write_id and self._event_escapes_buffer(node, dest_name) and not passed:
                    return False

                if nid in reject_safe:
                    saw_reject = True
                    true_succ = node.successors[0]
                    safe_succ = reject_safe[nid]
                    # Overflow / bail path: do not mark passed.
                    queue.append((true_succ, passed))
                    if safe_succ == -1:
                        # No else branch encoded; remaining successors after true are safe.
                        for succ in node.successors[1:]:
                            queue.append((succ, True))
                    else:
                        queue.append((safe_succ, True))
                    continue

                for succ in node.successors:
                    queue.append((succ, passed))

            if not saw_reject:
                return False
        return True

    def _report(
        self,
        file_path: str,
        ast_ctx: CASTContext,
        line_no: int,
        column: int,
        callee: str,
        capacity: int,
        detail: str,
    ) -> Issue:
        return self.create_issue(
            file_path=file_path,
            line_number=line_no,
            code_snippet=_source_snippet(ast_ctx, line_no, f"{callee}(...);"),
            message=(
                f"'{callee}' writes to a {capacity}-byte destination, but {detail}; "
                "buffer capacity is not proven sufficient on all paths."
            ),
            column_number=column,
            engine="AST",
            fix_type=FixType.MANUAL_REVIEW,
        )

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return []

        from pycparser import c_ast

        issues: List[Issue] = []
        for fn in ast_ctx.functions:
            funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
            if funcdef is None or funcdef.body is None:
                continue

            line_offset = (
                funcdef.decl.coord.line - fn.start_line
                if funcdef.decl.coord is not None
                else 0
            )
            outer = self

            class CallVisitor(c_ast.NodeVisitor):
                def visit_FuncCall(self, node):
                    if not isinstance(node.name, c_ast.ID) or node.name.name not in outer.TARGET_FUNCS:
                        self.generic_visit(node)
                        return
                    callee = node.name.name
                    args = [_format_pycparser_expr(arg) for arg in (node.args.exprs if node.args else [])]
                    line_no = (node.coord.line - line_offset) if node.coord else fn.start_line
                    column = getattr(node.coord, "column", 1) if node.coord else 1

                    if callee == "gets":
                        if not args:
                            return
                        capacity = outer._resolve_dest_capacity(args[0], fn, line_no, ast_ctx)
                        if capacity is not None:
                            issues.append(outer._report(
                                file_path,
                                ast_ctx,
                                line_no,
                                column,
                                callee,
                                capacity,
                                "the input API has no maximum-length argument",
                            ))
                        return

                    if callee == "scanf":
                        if len(args) < 2:
                            return
                        for dest, width, conversion in outer._scanf_string_destinations(args[0], args[1:]):
                            capacity = outer._resolve_dest_capacity(dest, fn, line_no, ast_ctx)
                            if capacity is None:
                                continue
                            required = None if width is None else width + 1
                            if required is None or required > capacity:
                                display = "%s" if conversion == "s" else "%["
                                detail = (
                                    f"the {display} conversion is unbounded"
                                    if width is None
                                    else f"the %{width}{'s' if conversion == 's' else '['} conversion can write "
                                    f"{required} bytes including NUL"
                                )
                                issues.append(outer._report(
                                    file_path, ast_ctx, line_no, column, callee, capacity, detail
                                ))
                        return

                    if len(args) < 2:
                        return
                    capacity = outer._resolve_dest_capacity(args[0], fn, line_no, ast_ctx)
                    if capacity is None:
                        return

                    if callee == "strcpy":
                        extent = outer._string_source_extent(args[1], fn, line_no, ast_ctx)
                        if extent is not None and extent <= capacity:
                            return
                        detail = (
                            f"source may require {extent} bytes including NUL"
                            if extent is not None
                            else f"source extent '{args[1]}' is data-dependent"
                        )
                        issues.append(outer._report(
                            file_path, ast_ctx, line_no, column, callee, capacity, detail
                        ))
                        return

                    if callee == "strcat":
                        source_extent = outer._string_source_extent(args[1], fn, line_no, ast_ctx)
                        current_len = outer._known_dest_string_length(args[0], fn, line_no, ast_ctx)
                        if source_extent is not None and current_len is not None:
                            required = current_len + source_extent
                            if required <= capacity:
                                return
                            detail = f"existing and appended strings may require {required} bytes"
                        else:
                            detail = "the resulting concatenated string extent is data-dependent"
                        issues.append(outer._report(
                            file_path, ast_ctx, line_no, column, callee, capacity, detail
                        ))
                        return

                    if callee == "sprintf":
                        fmt_len = outer._literal_string_length(args[1])
                        if fmt_len is not None:
                            try:
                                fmt = ast.literal_eval(
                                    re.sub(r'^(?:u8|u|U|L)', '', args[1].strip())
                                )
                            except (SyntaxError, ValueError):
                                fmt = None
                            if fmt is not None and re.search(r'%(?!%)', fmt) is None:
                                required = len(fmt.replace('%%', '%')) + 1
                                if required <= capacity:
                                    return
                                if outer._has_post_sprintf_length_defense(
                                    funcdef, ast_ctx, args[0], line_no
                                ):
                                    return
                                detail = f"formatted output requires {required} bytes including NUL"
                                issues.append(outer._report(
                                    file_path, ast_ctx, line_no, column, callee, capacity, detail
                                ))
                                return
                        if outer._has_post_sprintf_length_defense(
                            funcdef, ast_ctx, args[0], line_no
                        ):
                            return
                        issues.append(outer._report(
                            file_path,
                            ast_ctx,
                            line_no,
                            column,
                            callee,
                            capacity,
                            "formatted output length is data-dependent",
                        ))

            CallVisitor().visit(funcdef.body)

        return issues
