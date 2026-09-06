"""
Rules for Arrays, Integer Overflows, VLAs, Bitwise Operations, and Magic Numbers.
"""

import re
from typing import List, Set

from ..base import BaseRule
from ...models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ...ast_analyzer import CASTContext


class ArithmeticIntegerOverflowRule(BaseRule):
    """Detect unchecked integer arithmetic, including external-input flows.

    The lightweight taint model treats values originating from ``atoi``,
    ``atol``, ``atoll``, ``strtol``, ``strtoul``, ``strtoll``, ``strtoull``,
    ``getenv``, ``fgets``, ``read``, ``recv``, ``recvfrom``, and command-line
    ``argv`` references as untrusted. Taint propagates through simple
    assignments and is cleared by a later assignment from a non-tainted value.
    Arithmetic on a tainted operand is reported unless a preceding comparison or
    assertion guards that operand. The existing MAX-constant and allocation-size
    checks remain additive fallbacks.
    """

    rule_id = "CGULL-006"
    name = "Arithmetic Integer Overflow"
    impact = Severity.HIGH
    category = RuleCategory.ARITHMETIC
    description = "Detect arithmetic operations (+, -, *, <<) on integers that lack preceding bounds checks, especially on external input or in allocation sizes."
    implementation_method = "AST parsing with lightweight external-input taint tracking and bounds-guard recognition"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-190 / CWE-680"
    remediation_suggestion = "Validate arithmetic operands before multiplication or addition: if (count > SIZE_MAX / sizeof(type)) return -EOVERFLOW;"
    sample_vulnerable_code = "size_t total = count * sizeof(int);\nint *buf = malloc(total); // Integer multiplication overflow"
    sample_remediated_code = "if (count > SIZE_MAX / sizeof(int)) return -EINVAL;\nint *buf = malloc(count * sizeof(int));"
    analysis_engine = AnalysisEngine.HYBRID

    MAX_CONSTANTS_PATTERN = re.compile(
        r"\b(?:INT_MAX|UINT_MAX|SIZE_MAX|SHRT_MAX|USHRT_MAX|LONG_MAX|ULONG_MAX|LLONG_MAX|ULLONG_MAX|INT32_MAX|UINT32_MAX|INT64_MAX|UINT64_MAX|CHAR_MAX|UCHAR_MAX|2147483647|4294967295|0x7f[fF]{6,14}|0x7[fF]{7}|0x[fF]{8,16})\b"
    )
    RETURN_TAINT_SOURCES = frozenset(
        {"atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull", "getenv"}
    )
    OUTPUT_TAINT_SOURCES = {
        "fgets": 0,
        "read": 1,
        "recv": 1,
        "recvfrom": 1,
    }
    ASSIGNMENT_PATTERN = re.compile(
        r"(?<![!=<>\+\-\*\/%&|^])\b([A-Za-z_]\w*)\s*=\s*([^;=]+)"
    )
    ARITHMETIC_PATTERN = re.compile(
        r"\b([A-Za-z_]\w*|\d+)\s*(\+=|-=|\*=|<<=|<<|[+\-*])\s*([A-Za-z_]\w*|\d+)\b"
    )
    INCDEC_PATTERN = re.compile(
        r"(?:\b([A-Za-z_]\w*)\s*(\+\+|--)|(?:\+\+|--)\s*\b([A-Za-z_]\w*)\b)"
    )
    ALLOCATION_PATTERN = re.compile(
        r"\b(?:malloc|calloc|realloc|aligned_alloc)\s*\(\s*([^)]+)\)"
    )

    def _has_preceding_overflow_check(
        self, source_lines: List[str], line_no: int, var_names: List[str]
    ) -> bool:
        """Return whether a nearby conditional/assertion bounds one operand."""
        if line_no < 1 or line_no > len(source_lines):
            return False

        from ...utils import strip_comments_keep_lines

        start_line = max(0, line_no - 16)
        preceding_slice = source_lines[start_line : line_no - 1]

        for prev_l in reversed(preceding_slice):
            _, clean_single = strip_comments_keep_lines(prev_l)
            p_strip = clean_single.strip()
            if not p_strip or p_strip.startswith("#"):
                continue
            if not re.search(r"\b(?:if|while|assert|ASSERT)\b", p_strip):
                continue

            refs_var = any(
                re.search(r"\b" + re.escape(v) + r"\b", p_strip)
                for v in var_names
                if v and not v.isdigit()
            )
            if not refs_var:
                continue

            if any(
                m_const in p_strip
                for m_const in ("SIZE_MAX", "INT_MAX", "UINT_MAX", "MAX_", "MIN_")
            ):
                return True

            for v_name in var_names:
                if not v_name or v_name.isdigit():
                    continue
                v_esc = re.escape(v_name)
                if (
                    re.search(r"\b" + v_esc + r"\b\s*(?:<|<=|>|>=)", p_strip)
                    or re.search(r"(?:<|<=|>|>=)\s*\b" + v_esc + r"\b", p_strip)
                    or re.search(r"\bassert\s*\([^)]*?\b" + v_esc + r"\b", p_strip)
                ):
                    return True
        return False

    @classmethod
    def _references_any(cls, expression: str, names: Set[str]) -> bool:
        return any(re.search(r"\b" + re.escape(name) + r"\b", expression) for name in names)

    @classmethod
    def _update_taint(cls, line: str, tainted: Set[str]) -> None:
        """Apply one source-order taint transfer to a single source line."""
        for function, argument_index in cls.OUTPUT_TAINT_SOURCES.items():
            call = re.search(r"\b" + re.escape(function) + r"\s*\(([^;]*)", line)
            if not call:
                continue
            args = [arg.strip() for arg in call.group(1).split(",")]
            if argument_index < len(args):
                match = re.search(r"\b([A-Za-z_]\w*)\b", args[argument_index])
                if match:
                    tainted.add(match.group(1))

        assignment = cls.ASSIGNMENT_PATTERN.search(line)
        if not assignment:
            return

        target = assignment.group(1)
        expression = assignment.group(2).strip()
        return_source = any(
            re.search(r"\b" + re.escape(function) + r"\s*\(", expression)
            for function in cls.RETURN_TAINT_SOURCES
        )
        from_argv = bool(re.search(r"\bargv\s*\[", expression))
        if return_source or from_argv or cls._references_any(expression, tainted):
            tainted.add(target)
        else:
            tainted.discard(target)

    def _append_general_issue(
        self,
        issues: List[Issue],
        reported_lines: Set[tuple],
        *,
        file_path: str,
        ast_ctx: CASTContext,
        line_no: int,
        line: str,
        column: int,
        lhs: str,
        op: str,
        rhs: str,
        tainted: bool,
    ) -> None:
        if self._has_preceding_overflow_check(ast_ctx.source_lines, line_no, [lhs, rhs]):
            return
        key = (line_no, lhs, op, rhs)
        if key in reported_lines:
            return
        reported_lines.add(key)
        snippet = (
            ast_ctx.source_lines[line_no - 1].strip()
            if line_no <= len(ast_ctx.source_lines)
            else line.strip()
        )
        if tainted:
            message = (
                f"Potential Integer Overflow (CWE-190): unchecked arithmetic '{lhs} {op} {rhs}' "
                "uses data derived from an external input source."
            )
        else:
            message = (
                f"Potential Integer Overflow (CWE-190): unchecked arithmetic '{lhs} {op} {rhs}' "
                "on variable or constant assigned near maximum integer value."
            )
        issues.append(
            self.create_issue(
                file_path=file_path,
                line_number=line_no,
                code_snippet=snippet,
                message=message,
                column_number=column,
                engine="AST",
                fix_type=FixType.MANUAL_REVIEW,
            )
        )

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues: List[Issue] = []
        reported_lines: Set[tuple] = set()

        for fn in ast_ctx.functions:
            body_lines = fn.body.splitlines()
            body_start = getattr(fn, "body_start_line", fn.start_line)
            max_assigned_vars: Set[str] = set()

            for line in body_lines:
                assignment = self.ASSIGNMENT_PATTERN.search(line)
                if assignment and self.MAX_CONSTANTS_PATTERN.search(assignment.group(2)):
                    max_assigned_vars.add(assignment.group(1))

            for i, line in enumerate(body_lines):
                line_no = body_start + i
                for m_alloc in self.ALLOCATION_PATTERN.finditer(line):
                    arg_str = m_alloc.group(1).strip()
                    m_arith = re.search(r"\b([A-Za-z_]\w*)\s*([*+])\s*([^,;)]+)", arg_str)
                    if not m_arith:
                        continue
                    var1, op, var2 = m_arith.group(1), m_arith.group(2), m_arith.group(3).strip()
                    if self._has_preceding_overflow_check(ast_ctx.source_lines, line_no, [var1, var2]):
                        continue
                    key = (line_no, var1, op, var2)
                    if key in reported_lines:
                        continue
                    reported_lines.add(key)
                    snippet = (
                        ast_ctx.source_lines[line_no - 1].strip()
                        if line_no <= len(ast_ctx.source_lines)
                        else line.strip()
                    )
                    guard_expr = (
                        f"{var1} > SIZE_MAX - ({var2})"
                        if op == "+"
                        else f"{var1} > SIZE_MAX / ({var2})"
                    )
                    issues.append(
                        self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=(
                                f"Unchecked integer arithmetic '{var1} {op} {var2}' in memory "
                                "allocation argument. May wrap around to small buffer causing heap corruption."
                            ),
                            column_number=m_alloc.start() + 1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({guard_expr}) return -EOVERFLOW;\n{snippet}",
                        )
                    )

            tainted_vars: Set[str] = set()
            for i, line in enumerate(body_lines):
                line_no = body_start + i
                self._update_taint(line, tainted_vars)

                if line.lstrip().startswith("for ") or line.lstrip().startswith("for("):
                    continue

                for match in self.ARITHMETIC_PATTERN.finditer(line):
                    lhs, op, rhs = match.group(1), match.group(2), match.group(3)
                    if lhs.isdigit() and rhs.isdigit():
                        continue
                    tainted = lhs in tainted_vars or rhs in tainted_vars
                    is_max_op = (
                        lhs in max_assigned_vars
                        or rhs in max_assigned_vars
                        or bool(self.MAX_CONSTANTS_PATTERN.search(lhs))
                        or bool(self.MAX_CONSTANTS_PATTERN.search(rhs))
                    )
                    if tainted or is_max_op:
                        self._append_general_issue(
                            issues,
                            reported_lines,
                            file_path=file_path,
                            ast_ctx=ast_ctx,
                            line_no=line_no,
                            line=line,
                            column=match.start() + 1,
                            lhs=lhs,
                            op=op,
                            rhs=rhs,
                            tainted=tainted,
                        )

                for match in self.INCDEC_PATTERN.finditer(line):
                    variable = match.group(1) or match.group(3)
                    if variable not in tainted_vars:
                        continue
                    operator = match.group(2) or ("++" if "++" in match.group(0) else "--")
                    self._append_general_issue(
                        issues,
                        reported_lines,
                        file_path=file_path,
                        ast_ctx=ast_ctx,
                        line_no=line_no,
                        line=line,
                        column=match.start() + 1,
                        lhs=variable,
                        op=operator,
                        rhs="1",
                        tainted=True,
                    )

        return issues

    def scan_line(
        self,
        file_path: str,
        line_number: int,
        line_content: str,
        full_code: str,
        source_lines: List[str],
        masked_line_content: str = "",
    ) -> List[Issue]:
        issues = []
        target_line = masked_line_content or line_content

        m = re.search(
            r"\b(?:malloc|calloc|realloc|aligned_alloc)\s*\(\s*(\w+)\s*([*+])\s*([^)]+)\)",
            target_line,
        )
        if m:
            var1, op, var2 = m.group(1), m.group(2), m.group(3).strip()
            if not self._has_preceding_overflow_check(source_lines, line_number, [var1, var2]):
                guard_expr = (
                    f"{var1} > SIZE_MAX - ({var2})"
                    if op == "+"
                    else f"{var1} > SIZE_MAX / ({var2})"
                )
                issues.append(
                    self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=(
                            f"Unchecked integer arithmetic '{var1} {op} {var2}' in memory allocation "
                            "argument. May wrap around to small buffer causing heap corruption."
                        ),
                        column_number=m.start() + 1,
                        engine="Regex",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=f"if ({guard_expr}) return -EOVERFLOW;\n{line_content.strip()}",
                    )
                )

        if self.MAX_CONSTANTS_PATTERN.search(target_line) and not target_line.lstrip().startswith("#"):
            for match in self.ARITHMETIC_PATTERN.finditer(target_line):
                lhs, op, rhs = match.group(1), match.group(2), match.group(3)
                if not (
                    self.MAX_CONSTANTS_PATTERN.search(lhs)
                    or self.MAX_CONSTANTS_PATTERN.search(rhs)
                ):
                    continue
                if self._has_preceding_overflow_check(source_lines, line_number, [lhs, rhs]):
                    continue
                issues.append(
                    self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=(
                            f"Potential Integer Overflow (CWE-190): unchecked arithmetic '{lhs} {op} {rhs}' "
                            "on variable or constant assigned near maximum integer value."
                        ),
                        column_number=match.start() + 1,
                        engine="Regex",
                        fix_type=FixType.MANUAL_REVIEW,
                    )
                )

        return issues
