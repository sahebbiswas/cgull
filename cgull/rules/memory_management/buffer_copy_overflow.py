"""Data-flow buffer overflow detection for classic copy and format APIs."""

import ast
import re
from typing import List, Optional, Tuple

from ...ast_analyzer import CASTContext, _format_pycparser_expr
from ...cfg import find_function_def
from ...models import AnalysisEngine, FixType, Issue, RuleCategory, Severity
from .helpers import _source_snippet
from .memcpy_struct_member_overflow import MemcpyStructMemberOverflowRule


class BufferCopyOverflowRule(MemcpyStructMemberOverflowRule):
    """Detect writes whose required extent cannot be proven to fit a known buffer."""

    rule_id = "CGULL-048"
    name = "Data-Flow Buffer Copy Overflow"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = (
        "Detect classic string/memory copy and format calls where destination capacity is "
        "known but the write extent cannot be proven to fit on all paths."
    )
    implementation_method = "AST destination-capacity reasoning with CFG bounds checks"
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

    TARGET_FUNCS = {"strcpy", "strcat", "sprintf", "gets", "memcpy", "memmove", "scanf"}

    @staticmethod
    def _literal_string_length(expr: str) -> Optional[int]:
        """Return the C string payload length, excluding the trailing NUL."""
        text = expr.strip()
        # pycparser formatting can preserve concatenated string tokens; v1 only folds a
        # single literal because treating an uncertain expression as unknown is safer.
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
            elif known is not None and re.search(rf'\b(?:strcat|sprintf|gets|scanf)\s*\([^;]*\b{re.escape(name)}\b', text):
                known = None
        return known

    @staticmethod
    def _scanf_string_destinations(format_expr: str, args: List[str]) -> List[Tuple[str, Optional[int]]]:
        """Return (%s destination, width) pairs for simple scanf format literals."""
        if not re.fullmatch(r'(?:u8|u|U|L)?"(?:\\.|[^"\\])*"', format_expr.strip()):
            return []
        try:
            fmt = ast.literal_eval(re.sub(r'^(?:u8|u|U|L)', '', format_expr.strip()))
        except (SyntaxError, ValueError):
            return []
        conversions = re.findall(r'%(?!%)(?:\*)?(\d+)?(?:hh|h|ll|l|j|z|t|L)?([A-Za-z\[])', fmt)
        result: List[Tuple[str, Optional[int]]] = []
        arg_index = 0
        for width, conv in conversions:
            if arg_index >= len(args):
                break
            # Assignment-suppressed conversions do not consume an argument.
            token_match = re.search(r'%(?!%)(\*)?(?:\d+)?(?:hh|h|ll|l|j|z|t|L)?' + re.escape(conv), fmt)
            if token_match and token_match.group(1):
                continue
            if conv == 's':
                result.append((args[arg_index], int(width) if width else None))
            arg_index += 1
        return result

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
            engine="AST/CFG",
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

                    if callee in {"memcpy", "memmove"}:
                        if len(args) < 3:
                            return
                        capacity = outer._resolve_dest_capacity(args[0], fn, line_no, ast_ctx)
                        if capacity is None:
                            return
                        const_size, size_expr = outer._resolve_size_arg(args[2], fn, line_no, ast_ctx)
                        if const_size is not None:
                            if const_size > capacity:
                                issues.append(outer._report(
                                    file_path, ast_ctx, line_no, column, callee, capacity,
                                    f"the requested write is {const_size} bytes",
                                ))
                            return
                        if size_expr and re.fullmatch(r'[A-Za-z_]\w*', size_expr.strip()):
                            if outer._is_size_var_gated(size_expr.strip(), capacity, fn, line_no, ast_ctx):
                                return
                        issues.append(outer._report(
                            file_path, ast_ctx, line_no, column, callee, capacity,
                            f"write extent '{args[2]}' is not bounded by the destination",
                        ))
                        return

                    if callee == "gets":
                        if not args:
                            return
                        capacity = outer._resolve_dest_capacity(args[0], fn, line_no, ast_ctx)
                        if capacity is not None:
                            issues.append(outer._report(
                                file_path, ast_ctx, line_no, column, callee, capacity,
                                "the input API has no maximum-length argument",
                            ))
                        return

                    if callee == "scanf":
                        if len(args) < 2:
                            return
                        for dest, width in outer._scanf_string_destinations(args[0], args[1:]):
                            capacity = outer._resolve_dest_capacity(dest, fn, line_no, ast_ctx)
                            if capacity is None:
                                continue
                            required = None if width is None else width + 1
                            if required is None or required > capacity:
                                detail = (
                                    "the %s conversion is unbounded"
                                    if width is None
                                    else f"the %{width}s conversion can write {required} bytes including NUL"
                                )
                                issues.append(outer._report(
                                    file_path, ast_ctx, line_no, column, callee, capacity, detail,
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
                        issues.append(outer._report(file_path, ast_ctx, line_no, column, callee, capacity, detail))
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
                        issues.append(outer._report(file_path, ast_ctx, line_no, column, callee, capacity, detail))
                        return

                    if callee == "sprintf":
                        fmt_len = outer._literal_string_length(args[1])
                        # A literal with no active conversions has an exact output extent.
                        if fmt_len is not None:
                            try:
                                fmt = ast.literal_eval(re.sub(r'^(?:u8|u|U|L)', '', args[1].strip()))
                            except (SyntaxError, ValueError):
                                fmt = None
                            if fmt is not None and re.search(r'%(?!%)', fmt) is None:
                                required = len(fmt.replace('%%', '%')) + 1
                                if required <= capacity:
                                    return
                                detail = f"formatted output requires {required} bytes including NUL"
                                issues.append(outer._report(file_path, ast_ctx, line_no, column, callee, capacity, detail))
                                return
                        issues.append(outer._report(
                            file_path, ast_ctx, line_no, column, callee, capacity,
                            "formatted output length is data-dependent",
                        ))

            CallVisitor().visit(funcdef.body)

        return issues
