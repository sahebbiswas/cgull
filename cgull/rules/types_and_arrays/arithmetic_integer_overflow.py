"""
Rules for Arrays, Integer Overflows, VLAs, Bitwise Operations, and Magic Numbers.
"""

import logging
import re
from typing import List, Set

from ..base import BaseRule
from ...ast_analyzer import CASTContext
from ...models import AnalysisEngine, FixType, Issue, RuleCategory, Severity

logger = logging.getLogger(__name__)


class ArithmeticIntegerOverflowRule(BaseRule):
    """Detect unchecked integer arithmetic, including external-input-derived values.

    The lightweight provenance pass recognizes these built-in trust-boundary
    sources: command-line ``argv`` references; ``getenv`` return values;
    integer conversions through ``atoi``, ``atol``, ``strtol``, ``strtoul``,
    ``strtoll`` and ``strtoull`` when their input is already untrusted; and
    buffers written by ``fgets``, ``read``, ``recv`` and ``recvfrom``.

    Taint is propagated through simple assignments and cleared by assignments
    that no longer reference tainted input. Arithmetic on tainted values is
    reported unless a preceding directionally relevant bounds/assert guard
    constrains the operand. Existing MAX-constant and allocation-argument checks
    remain additive fallbacks.
    """

    rule_id = "CGULL-006"
    name = "Arithmetic Integer Overflow"
    impact = Severity.HIGH
    category = RuleCategory.ARITHMETIC
    description = "Detect arithmetic operations (+, -, *, <<) on integers that lack preceding bounds checks, especially in allocation sizes or offsets."
    implementation_method = "AST parsing with lightweight external-input provenance and bounds-guard detection"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-190 / CWE-680"
    remediation_suggestion = "Validate arithmetic operands before multiplication or addition: if (count > SIZE_MAX / sizeof(type)) return -EOVERFLOW;"
    sample_vulnerable_code = "size_t total = count * sizeof(int);\nint *buf = malloc(total); // Integer multiplication overflow"
    sample_remediated_code = "if (count > SIZE_MAX / sizeof(int)) return -EINVAL;\nint *buf = malloc(count * sizeof(int));"
    analysis_engine = AnalysisEngine.HYBRID

    MAX_CONSTANTS_PATTERN = re.compile(
        r'\b(?:INT_MAX|UINT_MAX|SIZE_MAX|SHRT_MAX|USHRT_MAX|LONG_MAX|ULONG_MAX|LLONG_MAX|ULLONG_MAX|INT32_MAX|UINT32_MAX|INT64_MAX|UINT64_MAX|CHAR_MAX|UCHAR_MAX|2147483647|4294967295|0x7f[fF]{6,14}|0x7[fF]{7}|0x[fF]{8,16})\b'
    )
    ASSIGNMENT_PATTERN = re.compile(
        r'(?<![!=<>\+\-\*\/%&|^])\b([A-Za-z_]\w*)\s*=\s*([^;=]+)'
    )
    ARITH_EXPR_PATTERN = re.compile(
        r'\b([A-Za-z_]\w*|\d+)\s*([\+\-\*]|<<|\+=|-=|\*=|\<<=)\s*([A-Za-z_]\w*|\d+)\b'
    )
    INC_DEC_PATTERN = re.compile(
        r'(?:\b([A-Za-z_]\w*)\s*(\+\+|--)|(?:\+\+|--)\s*\b([A-Za-z_]\w*))'
    )
    INTEGER_CONVERSION_PATTERN = re.compile(
        r'\b(?:atoi|atol|strtol|strtoul|strtoll|strtoull)\s*\('
    )
    DIRECT_RETURN_SOURCE_PATTERN = re.compile(r'\bgetenv\s*\(')
    BUFFER_SOURCE_PATTERNS = (
        re.compile(r'\bfgets\s*\(\s*([A-Za-z_]\w*)\s*,'),
        re.compile(r'\bread\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*,'),
        re.compile(r'\brecv\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*,'),
        re.compile(r'\brecvfrom\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*,'),
    )

    def _has_preceding_overflow_check(
        self,
        source_lines: List[str],
        line_no: int,
        var_names: List[str],
        *,
        bound_direction: str | None = None,
    ) -> bool:
        """Return whether a recent guard constrains an operand in the needed direction."""
        if line_no < 1 or line_no > len(source_lines):
            return False

        from ...utils import strip_comments_keep_lines

        start_line = max(0, line_no - 16)
        preceding_slice = source_lines[start_line:line_no - 1]

        for prev_l in reversed(preceding_slice):
            _, clean_single = strip_comments_keep_lines(prev_l)
            p_strip = clean_single.strip()
            if not p_strip or p_strip.startswith('#'):
                continue
            if not re.search(r'\b(?:if|while|assert|ASSERT)\b', p_strip):
                continue

            refs_var = any(
                bool(re.search(r'\b' + re.escape(v) + r'\b', p_strip))
                for v in var_names
                if v and not v.isdigit()
            )
            if not refs_var:
                continue

            if bound_direction is None and any(
                marker in p_strip for marker in ("SIZE_MAX", "INT_MAX", "UINT_MAX", "MAX_", "MIN_")
            ):
                return True
            if bound_direction == "upper" and any(
                marker in p_strip for marker in ("SIZE_MAX", "INT_MAX", "UINT_MAX", "MAX_")
            ):
                return True
            if bound_direction == "lower" and "MIN_" in p_strip:
                return True

            for v_name in var_names:
                if not v_name or v_name.isdigit():
                    continue
                v_esc = re.escape(v_name)
                if bound_direction == "upper":
                    if (
                        re.search(r'\b' + v_esc + r'\b\s*(?:<|<=)', p_strip)
                        or re.search(r'(?:>|>=)\s*\b' + v_esc + r'\b', p_strip)
                    ):
                        return True
                    continue
                if bound_direction == "lower":
                    if (
                        re.search(r'\b' + v_esc + r'\b\s*(?:>|>=)', p_strip)
                        or re.search(r'(?:<|<=)\s*\b' + v_esc + r'\b', p_strip)
                    ):
                        return True
                    continue
                if (
                    re.search(r'\b' + v_esc + r'\b\s*(?:<|<=|>|>=)', p_strip)
                    or re.search(r'(?:<|<=|>|>=)\s*\b' + v_esc + r'\b', p_strip)
                    or re.search(r'\bassert\s*\([^)]*?\b' + v_esc + r'\b', p_strip)
                ):
                    return True

        return False

    @staticmethod
    def _required_bound_direction(operator: str) -> str:
        return "lower" if operator in {"-", "-=", "--"} else "upper"

    @staticmethod
    def _references_any(expr: str, names: Set[str]) -> bool:
        return any(re.search(r'\b' + re.escape(name) + r'\b', expr) for name in names)

    @staticmethod
    def _argv_names(fn) -> Set[str]:
        names: Set[str] = set()
        for param in getattr(fn, "parameters", ()):
            name = getattr(param, "name", "")
            if name and (name == "argv" or "argv" in name.lower()):
                names.add(name)
        return names

    def _update_external_input_taint(self, line: str, tainted: Set[str], argv_names: Set[str]) -> None:
        for pattern in self.BUFFER_SOURCE_PATTERNS:
            for match in pattern.finditer(line):
                tainted.add(match.group(1))

        assignment = self.ASSIGNMENT_PATTERN.search(line)
        if not assignment:
            return
        target = assignment.group(1)
        expr = assignment.group(2)
        refs_argv = self._references_any(expr, argv_names) or bool(re.search(r'\bargv\s*\[', expr))
        refs_tainted = self._references_any(expr, tainted)
        direct_return_source = bool(self.DIRECT_RETURN_SOURCE_PATTERN.search(expr))
        conversion_from_untrusted = bool(self.INTEGER_CONVERSION_PATTERN.search(expr)) and (
            refs_tainted or refs_argv or direct_return_source
        )
        if refs_argv or refs_tainted or conversion_from_untrusted or direct_return_source:
            tainted.add(target)
        else:
            tainted.discard(target)

    def _append_tainted_issue(
        self,
        issues: List[Issue],
        reported_lines: Set[tuple],
        *,
        file_path: str,
        ast_ctx: CASTContext,
        line: str,
        line_no: int,
        expression: str,
        operator: str,
        operands: List[str],
        column_number: int,
        dedup_key: tuple,
    ) -> None:
        if self._has_preceding_overflow_check(
            ast_ctx.source_lines,
            line_no,
            operands,
            bound_direction=self._required_bound_direction(operator),
        ):
            return
        if dedup_key in reported_lines:
            return
        reported_lines.add(dedup_key)
        snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
        issues.append(self.create_issue(
            file_path=file_path,
            line_number=line_no,
            code_snippet=snippet,
            message=(
                f"Potential Integer Overflow (CWE-190): unchecked arithmetic '{expression}' "
                "uses a value derived from external input without a preceding bounds check."
            ),
            column_number=column_number,
            engine="AST",
            fix_type=FixType.MANUAL_REVIEW,
        ))

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues: List[Issue] = []
        reported_lines: Set[tuple] = set()

        for fn in ast_ctx.functions:
            body_lines = fn.body.splitlines()
            body_start = getattr(fn, "body_start_line", fn.start_line)
            max_assigned_vars: Set[str] = set()

            for line in body_lines:
                m_assign = self.ASSIGNMENT_PATTERN.search(line)
                if m_assign and self.MAX_CONSTANTS_PATTERN.search(m_assign.group(2)):
                    max_assigned_vars.add(m_assign.group(1))

            alloc_pattern = re.compile(r'\b(?:malloc|calloc|realloc|aligned_alloc)\s*\(\s*([^)]+)\)')
            for i, line in enumerate(body_lines):
                line_no = body_start + i
                for m_alloc in alloc_pattern.finditer(line):
                    arg_str = m_alloc.group(1).strip()
                    m_arith = re.search(r'\b([A-Za-z_]\w*)\s*([\*\+])\s*([^,;)]+)', arg_str)
                    if not m_arith:
                        continue
                    var1 = m_arith.group(1)
                    op = m_arith.group(2)
                    var2 = m_arith.group(3).strip()
                    if var1.isdigit() and var2.isdigit():
                        continue
                    if self._has_preceding_overflow_check(ast_ctx.source_lines, line_no, [var1, var2]):
                        continue
                    key = (line_no, var1, op, var2)
                    if key in reported_lines:
                        continue
                    reported_lines.add(key)
                    snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                    guard_expr = f"{var1} > SIZE_MAX - ({var2})" if op == "+" else f"{var1} > SIZE_MAX / ({var2})"
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        message=f"Unchecked integer arithmetic '{var1} {op} {var2}' in memory allocation argument. May wrap around to small buffer causing heap corruption.",
                        column_number=m_alloc.start() + 1,
                        engine="AST",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=f"if ({guard_expr}) return -EOVERFLOW;\n{snippet}",
                    ))

            tainted: Set[str] = set()
            argv_names = self._argv_names(fn)
            tainted.update(argv_names)

            for i, line in enumerate(body_lines):
                line_no = body_start + i
                self._update_external_input_taint(line, tainted, argv_names)
                stripped = line.lstrip()
                if stripped.startswith("for ") or stripped.startswith("for("):
                    continue

                for m_arith in self.ARITH_EXPR_PATTERN.finditer(line):
                    lhs = m_arith.group(1)
                    op = m_arith.group(2)
                    rhs = m_arith.group(3)
                    if lhs.isdigit() and rhs.isdigit() and not (
                        self.MAX_CONSTANTS_PATTERN.search(lhs) or self.MAX_CONSTANTS_PATTERN.search(rhs)
                    ):
                        continue
                    is_tainted_op = lhs in tainted or rhs in tainted
                    is_max_op = (
                        lhs in max_assigned_vars
                        or rhs in max_assigned_vars
                        or bool(self.MAX_CONSTANTS_PATTERN.search(lhs))
                        or bool(self.MAX_CONSTANTS_PATTERN.search(rhs))
                    )
                    key = (line_no, lhs, op, rhs)
                    if is_tainted_op:
                        self._append_tainted_issue(
                            issues,
                            reported_lines,
                            file_path=file_path,
                            ast_ctx=ast_ctx,
                            line=line,
                            line_no=line_no,
                            expression=f"{lhs} {op} {rhs}",
                            operator=op,
                            operands=[lhs, rhs],
                            column_number=m_arith.start() + 1,
                            dedup_key=key,
                        )
                    elif is_max_op and not self._has_preceding_overflow_check(ast_ctx.source_lines, line_no, [lhs, rhs]):
                        if key not in reported_lines:
                            reported_lines.add(key)
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Potential Integer Overflow (CWE-190): unchecked arithmetic '{lhs} {op} {rhs}' on variable or constant assigned near maximum integer value.",
                                column_number=m_arith.start() + 1,
                                engine="AST",
                                fix_type=FixType.MANUAL_REVIEW,
                            ))

                for m_inc in self.INC_DEC_PATTERN.finditer(line):
                    var_name = m_inc.group(1) or m_inc.group(3)
                    if var_name not in tainted:
                        continue
                    token = m_inc.group(2) or ("++" if "++" in m_inc.group(0) else "--")
                    self._append_tainted_issue(
                        issues,
                        reported_lines,
                        file_path=file_path,
                        ast_ctx=ast_ctx,
                        line=line,
                        line_no=line_no,
                        expression=f"{var_name}{token}",
                        operator=token,
                        operands=[var_name],
                        column_number=m_inc.start() + 1,
                        dedup_key=(line_no, var_name, token, ""),
                    )

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        target_line = masked_line_content or line_content

        m = re.search(r'\b(?:malloc|calloc|realloc|aligned_alloc)\s*\(\s*(\w+)\s*([\*\+])\s*([^)]+)\)', target_line)
        if m:
            var1 = m.group(1)
            op = m.group(2)
            var2 = m.group(3).strip()
            if not self._has_preceding_overflow_check(source_lines, line_number, [var1, var2]):
                guard_expr = f"{var1} > SIZE_MAX - ({var2})" if op == "+" else f"{var1} > SIZE_MAX / ({var2})"
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Unchecked integer arithmetic '{var1} {op} {var2}' in memory allocation argument. May wrap around to small buffer causing heap corruption.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"if ({guard_expr}) return -EOVERFLOW;\n{line_content.strip()}",
                ))

        if self.MAX_CONSTANTS_PATTERN.search(target_line) and not target_line.lstrip().startswith('#'):
            for m_arith in self.ARITH_EXPR_PATTERN.finditer(target_line):
                lhs = m_arith.group(1)
                op = m_arith.group(2)
                rhs = m_arith.group(3)
                if self.MAX_CONSTANTS_PATTERN.search(lhs) or self.MAX_CONSTANTS_PATTERN.search(rhs):
                    if not self._has_preceding_overflow_check(source_lines, line_number, [lhs, rhs]):
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=line_content,
                            message=f"Potential Integer Overflow (CWE-190): unchecked arithmetic '{lhs} {op} {rhs}' on variable or constant assigned near maximum integer value.",
                            column_number=m_arith.start() + 1,
                            engine="Regex",
                            fix_type=FixType.MANUAL_REVIEW,
                        ))

        return issues
