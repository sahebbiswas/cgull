"""
Rules for Arrays, Integer Overflows, VLAs, Bitwise Operations, and Magic Numbers.
"""

import re
import logging
from typing import Dict, List, Optional, Set, Tuple

from ..base import BaseRule
from ...models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ...ast_analyzer import CASTContext, is_unsigned_type

logger = logging.getLogger(__name__)
class ArithmeticIntegerOverflowRule(BaseRule):
    rule_id = "CGULL-006"
    name = "Arithmetic Integer Overflow"
    impact = Severity.HIGH
    category = RuleCategory.ARITHMETIC
    description = "Detect arithmetic operations (+, -, *, <<) on integers that lack preceding bounds checks, especially in allocation sizes or offsets."
    implementation_method = "AST parsing to find arithmetic expressions and verify bounds validation"
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

    def _has_preceding_overflow_check(self, source_lines: List[str], line_no: int, var_names: List[str]) -> bool:
        """
        Check if any preceding lines within a window (or function body) contain bounds/overflow checks
        for the given variable(s).
        """
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

            # Check if this line is an actual conditional/assert guard statement
            is_guard_stmt = bool(re.search(r'\b(?:if|while|assert|ASSERT)\b', p_strip))
            if not is_guard_stmt:
                continue

            # Ensure the guard statement references at least one variable involved in the arithmetic
            refs_var = any(
                bool(re.search(r'\b' + re.escape(v) + r'\b', p_strip))
                for v in var_names if v and not v.isdigit()
            )

            # Look for explicit bounds checks involving MAX/MIN constants in guard expressions for the variable(s)
            if refs_var and any(m_const in p_strip for m_const in ("SIZE_MAX", "INT_MAX", "UINT_MAX", "MAX_", "MIN_")):
                return True

            for v_name in var_names:
                if not v_name or v_name.isdigit():
                    continue
                v_esc = re.escape(v_name)
                if re.search(r'\b' + v_esc + r'\b\s*(?:<|<=|>|>=)', p_strip) or \
                   re.search(r'(?:<|<=|>|>=)\s*\b' + v_esc + r'\b', p_strip) or \
                   re.search(r'\bassert\s*\([^)]*?\b' + v_esc + r'\b', p_strip):
                    return True

        return False

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        reported_lines = set()

        for fn in ast_ctx.functions:
            body_lines = fn.body.splitlines()
            body_start = getattr(fn, "body_start_line", fn.start_line)

            # Track variables initialized or assigned from MAX constants
            max_assigned_vars = set()

            # 1. First pass over function body: identify variables holding max constants
            for i, line in enumerate(body_lines):
                # Check variable declarations or assignments: var = INT_MAX (excluding ==, !=, <=, >=, +=, etc.)
                m_assign = re.search(r'(?<![!=<>\+\-\*\/%&|^])\b([a-zA-Z_]\w*)\s*=\s*([^;=]+)', line)
                if m_assign:
                    v_name = m_assign.group(1).strip()
                    val_expr = m_assign.group(2).strip()
                    if self.MAX_CONSTANTS_PATTERN.search(val_expr):
                        max_assigned_vars.add(v_name)

            # 2. Check for malloc/calloc/realloc allocation arithmetic
            alloc_pattern = re.compile(
                r'\b(?:malloc|calloc|realloc|aligned_alloc)\s*\(\s*([^)]+)\)'
            )
            for i, line in enumerate(body_lines):
                line_no = body_start + i
                for m_alloc in alloc_pattern.finditer(line):
                    arg_str = m_alloc.group(1).strip()
                    # Check if argument contains arithmetic (+, *, <<) with non-constant identifiers
                    m_arith = re.search(r'\b([a-zA-Z_]\w*)\s*([\*\+])\s*([^,;)]+)', arg_str)
                    if m_arith:
                        var1 = m_arith.group(1)
                        op = m_arith.group(2)
                        var2 = m_arith.group(3).strip()

                        # Skip if pure numbers e.g. 1024
                        if var1.isdigit() and var2.isdigit():
                            continue

                        if not self._has_preceding_overflow_check(ast_ctx.source_lines, line_no, [var1, var2]):
                            key = (line_no, var1, op, var2)
                            if key not in reported_lines:
                                reported_lines.add(key)
                                snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                                guard_expr = f"{var1} > SIZE_MAX - ({var2})" if op == '+' else f"{var1} > SIZE_MAX / ({var2})"
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=line_no,
                                    code_snippet=snippet,
                                    message=f"Unchecked integer arithmetic '{var1} {op} {var2}' in memory allocation argument. May wrap around to small buffer causing heap corruption.",
                                    column_number=m_alloc.start() + 1,
                                    engine="AST",
                                    fix_type=FixType.SUGGESTED_FIX,
                                    suggested_fix_replacement=f"if ({guard_expr}) return -EOVERFLOW;\n{snippet}"
                                ))

            # 3. Check for general CWE-190 arithmetic integer overflow
            # Patterns like: result = data + 1; or data += 1; or data + INT_MAX; or 2147483647 + 1
            arith_expr_pattern = re.compile(
                r'\b([a-zA-Z_]\w*|\d+)\s*([\+\-\*]|<<|\+=|-=|\*=|\<<=)\s*([a-zA-Z_]\w*|\d+)\b'
            )

            for i, line in enumerate(body_lines):
                line_no = body_start + i
                # Skip for-loop headers (e.g. for (int i = 0; i < n; i++))
                if line.lstrip().startswith("for ") or line.lstrip().startswith("for("):
                    continue

                for m_arith in arith_expr_pattern.finditer(line):
                    lhs = m_arith.group(1)
                    op = m_arith.group(2)
                    rhs = m_arith.group(3)

                    # Skip pure small integer literals (e.g. 1 + 2)
                    if lhs.isdigit() and rhs.isdigit() and not (self.MAX_CONSTANTS_PATTERN.search(lhs) or self.MAX_CONSTANTS_PATTERN.search(rhs)):
                        continue

                    # Determine if this arithmetic operation involves a MAX assigned variable or MAX constant directly
                    is_max_op = (
                        lhs in max_assigned_vars or
                        rhs in max_assigned_vars or
                        bool(self.MAX_CONSTANTS_PATTERN.search(lhs)) or
                        bool(self.MAX_CONSTANTS_PATTERN.search(rhs))
                    )

                    if is_max_op:
                        if not self._has_preceding_overflow_check(ast_ctx.source_lines, line_no, [lhs, rhs]):
                            key = (line_no, lhs, op, rhs)
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

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        target_line = masked_line_content or line_content

        # Look for malloc(n * m) or malloc(n + m) or calloc expressions without bounds check
        m = re.search(r'\b(?:malloc|calloc|realloc|aligned_alloc)\s*\(\s*(\w+)\s*([\*\+])\s*([^)]+)\)', target_line)
        if m:
            var1 = m.group(1)
            op = m.group(2)
            var2 = m.group(3).strip()
            # Check if previous lines contained overflow checks
            has_overflow_check = self._has_preceding_overflow_check(source_lines, line_number, [var1, var2])

            if not has_overflow_check:
                guard_expr = f"{var1} > SIZE_MAX - ({var2})" if op == '+' else f"{var1} > SIZE_MAX / ({var2})"
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Unchecked integer arithmetic '{var1} {op} {var2}' in memory allocation argument. May wrap around to small buffer causing heap corruption.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"if ({guard_expr}) return -EOVERFLOW;\n{line_content.strip()}"
                ))

        # Also regex check for direct arithmetic on MAX constants in scan_line if scan_ast isn't run
        if self.MAX_CONSTANTS_PATTERN.search(target_line) and not target_line.lstrip().startswith('#'):
            arith_expr_pattern = re.compile(
                r'\b([a-zA-Z_]\w*|\d+)\s*([\+\-\*]|<<|\+=|-=|\*=|\<<=)\s*([a-zA-Z_]\w*|\d+)\b'
            )
            for m_arith in arith_expr_pattern.finditer(target_line):
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
