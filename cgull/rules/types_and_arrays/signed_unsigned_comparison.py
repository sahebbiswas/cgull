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
class SignedUnsignedComparisonRule(BaseRule):
    rule_id = "CGULL-033"
    name = "Signed/Unsigned Comparison and Loop-Bound Mismatch"
    impact = Severity.MEDIUM
    category = RuleCategory.ARITHMETIC
    description = "Detect comparisons between signed and unsigned integer types or loop bounds where implicit promotion causes infinite loops or unexpected comparison results."
    implementation_method = "AST parsing to evaluate underlying data types of comparison operands"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-195 / CERT INT02-C"
    remediation_suggestion = "Ensure loop variables and bounds share the same signedness, cast explicitly after verifying bounds, or use unsigned loop counters with condition (i > 0) or (i-- > 0)."
    sample_vulnerable_code = "size_t len = get_len();\nfor (int i = len; i >= 0; i--) {\n    /* ... */\n}\nif (signed_var < unsigned_var) { ... }"
    sample_remediated_code = "size_t len = get_len();\nfor (size_t i = len; i > 0; i--) {\n    use(i - 1);\n}"
    analysis_engine = AnalysisEngine.HYBRID

    @staticmethod
    def _is_unsigned_type(type_name: str, custom_typedefs: Optional[set] = None) -> bool:
        return is_unsigned_type(type_name, custom_typedefs)

    @staticmethod
    def _is_signed_type(type_name: str) -> bool:
        tn = type_name.lower()
        if "unsigned" in tn:
            return False
        for s_type in ("int", "short", "long", "char", "ssize_t", "int8_t", "int16_t", "int32_t", "int64_t", "intptr_t", "ptrdiff_t"):
            if re.search(r'\b' + re.escape(s_type) + r'\b', tn):
                return True
        return False

    @staticmethod
    def _is_pointer_like(obj) -> bool:
        """Pointers and arrays are addresses, not integer-rank operands (INT02-C is about integers)."""
        return bool(
            getattr(obj, "is_pointer", False)
            or getattr(obj, "is_array", False)
            or "*" in str(getattr(obj, "type_name", "") or "")
        )

    def _resolve_named_object(self, name: str, fn, ast_ctx):
        """Local variable, then parameter, then global with this name (nearest scope wins)."""
        if fn:
            var_obj = fn.variables.get(name)
            if var_obj:
                return var_obj
            for param in fn.parameters:
                if param.name == name:
                    return param
        if ast_ctx and name in ast_ctx.global_variables:
            return ast_ctx.global_variables[name]
        return None

    @staticmethod
    def _extend_left(line: str, pos: int) -> str:
        """Text of the operand expression that ends at *pos* (stops at the enclosing delimiter/operator)."""
        depth = 0
        i = pos
        while i > 0:
            ch = line[i - 1]
            if ch == ")":
                depth += 1
            elif ch == "(":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and (ch in ",;?:{}=<&|" or (ch == ">" and line[i - 2:i] != "->")):
                break
            i -= 1
        return line[i:pos]

    @staticmethod
    def _extend_right(line: str, pos: int) -> str:
        """Text of the operand expression that starts at *pos*."""
        depth = 0
        i = pos
        n = len(line)
        while i < n:
            ch = line[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and (
                ch in ",;?:{}=<&|"
                or (ch == ">" and line[i - 1:i] != "-")
                or (ch == "!" and line[i + 1:i + 2] == "=")
            ):
                break
            i += 1
        return line[pos:i]

    @staticmethod
    def _is_dereferenced(text: str, start: int, end: int) -> bool:
        """The identifier at ``text[start:end]`` is used as ``*p``, ``p[i]``, ``p->m`` or ``p.m`` (an integer-valued access)."""
        before = text[:start].rstrip()
        if before.endswith("*"):
            prior = before[:-1].rstrip()
            if not prior or not (prior[-1].isalnum() or prior[-1] in "_)]"):
                return True  # unary dereference
        return bool(re.match(r"\s*(?:\[|->|\.)", text[end:]))

    def _expression_has_pointer(self, text: str, fn, ast_ctx) -> bool:
        """True when a named pointer/array takes part in the expression as an address (``p + n``, ``p``)."""
        # ``sizeof(buf)`` is an unsigned integer, not an address, even when buf is an array.
        text = re.sub(r"\bsizeof\s*\((?:[^()]|\([^()]*\))*\)", " 0 ", text)
        text = re.sub(r"\bsizeof\s+[A-Za-z_]\w*", " 0 ", text)
        for match in re.finditer(r"(?<![\w.>])([A-Za-z_]\w*)\b(?!\s*\()", text):
            obj = self._resolve_named_object(match.group(1), fn, ast_ctx)
            if obj is None or not self._is_pointer_like(obj):
                continue
            if self._is_dereferenced(text, match.start(1), match.end(1)):
                continue
            return True
        return False

    def _get_var_signedness(self, var_expr: str, fn, ast_ctx, dereferenced: bool = False) -> Optional[bool]:
        """
        Returns True if unsigned, False if signed, or None if unknown/literal.
        var_expr can be a variable identifier, param name, or 'sizeof(...)'.
        A pointer or array used as an address is not an integer operand, so it is
        unknown (None); with ``dereferenced=True`` (``*p``) its pointee type decides.
        """
        expr_clean = var_expr.strip()
        if expr_clean.startswith("sizeof") or "sizeof(" in expr_clean:
            return True

        m = re.match(r'^[a-zA-Z_]\w*$', expr_clean)
        if not m:
            return None
        var_name = expr_clean

        custom_typedefs = getattr(ast_ctx, "unsigned_typedefs", None)
        if fn:
            var_obj = fn.variables.get(var_name)
            if var_obj:
                if self._is_pointer_like(var_obj) and not dereferenced:
                    return None
                if self._is_unsigned_type(var_obj.type_name, custom_typedefs) or not var_obj.is_signed:
                    return True
                if self._is_signed_type(var_obj.type_name) or var_obj.is_signed:
                    return False

            for param in fn.parameters:
                if param.name == var_name:
                    if self._is_pointer_like(param) and not dereferenced:
                        return None
                    if self._is_unsigned_type(param.type_name, custom_typedefs):
                        return True
                    if self._is_signed_type(param.type_name):
                        return False

        if ast_ctx and var_name in ast_ctx.global_variables:
            var_obj = ast_ctx.global_variables[var_name]
            if self._is_pointer_like(var_obj) and not dereferenced:
                return None
            if self._is_unsigned_type(var_obj.type_name, custom_typedefs) or not var_obj.is_signed:
                return True
            if self._is_signed_type(var_obj.type_name) or var_obj.is_signed:
                return False

        return None

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        reported_lines = set()

        def add_issue(line_no, snippet, msg, col=1):
            key = (line_no, msg)
            if key in reported_lines:
                return
            reported_lines.add(key)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_no,
                code_snippet=snippet,
                message=msg,
                column_number=col,
                engine="AST",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement="Ensure loop counter and bound share the same type/signedness, or use explicit bounds validation."
            ))

        for fn in ast_ctx.functions:
            body_lines = fn.body.splitlines()
            body_start = getattr(fn, "body_start_line", fn.start_line)

            # 1. Reverse loops and loop bound mismatches
            for_pattern = re.compile(
                r'\bfor\s*\(\s*(?:([a-zA-Z_]\w*(?:\s*\*)*)\s+)?([a-zA-Z_]\w*)\s*=\s*([^;]+);\s*([^;]+);\s*([^)]+)\)'
            )
            for i, line in enumerate(body_lines):
                line_no = body_start + i
                for m in for_pattern.finditer(line):
                    decl_type = m.group(1)
                    var_name = m.group(2)
                    init_expr = m.group(3).strip()
                    cond_expr = m.group(4).strip()
                    step_expr = m.group(5).strip()

                    var_is_unsigned = None
                    if decl_type:
                        var_is_unsigned = self._is_unsigned_type(decl_type, getattr(ast_ctx, "unsigned_typedefs", None))
                    else:
                        var_is_unsigned = self._get_var_signedness(var_name, fn, ast_ctx)

                    is_decrement_cond = bool(
                        re.search(r'\b' + re.escape(var_name) + r'\s*>=\s*0\b', cond_expr) or
                        re.search(r'\b' + re.escape(var_name) + r'\s*>\s*-1\b', cond_expr) or
                        re.search(r'\b0\s*<=\s*' + re.escape(var_name) + r'\b', cond_expr)
                    )
                    is_decrement_step = '--' in step_expr or '-=' in step_expr or f'{var_name} -' in step_expr

                    if is_decrement_cond and is_decrement_step:
                        if var_is_unsigned is True:
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                            add_issue(
                                line_no, snippet,
                                f"Infinite Loop Risk: unsigned loop variable '{var_name}' compared with '{var_name} >= 0' will always evaluate to true as unsigned types cannot be negative.",
                                col=m.start() + 1
                            )
                        elif var_is_unsigned is False:
                            init_signedness = self._get_var_signedness(init_expr, fn, ast_ctx)
                            if init_signedness is True:
                                snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                                add_issue(
                                    line_no, snippet,
                                    f"Loop Bound Mismatch: signed loop counter '{var_name}' initialized from unsigned bound '{init_expr}'. If '{init_expr}' exceeds INT_MAX, initialization wraps to negative.",
                                    col=m.start() + 1
                                )

            # 2. Signed vs Unsigned comparisons in conditionals/statements
            comp_pattern = re.compile(
                r'\b([a-zA-Z_]\w*|sizeof\s*\([^)]*\))\s*(<|<=|>|>=|==|!=)\s*([a-zA-Z_]\w*|sizeof\s*\([^)]*\)|-\d+)\b'
            )
            for i, line in enumerate(body_lines):
                line_no = body_start + i
                for m in comp_pattern.finditer(line):
                    left_expr = m.group(1).strip()
                    op = m.group(2)
                    right_expr = m.group(3).strip()

                    if ("for " in line or "while " in line) and (
                        re.search(r'\b' + re.escape(left_expr) + r'\s*>=\s*0\b', line) or
                        re.search(r'\b' + re.escape(left_expr) + r'\s*>\s*-1\b', line) or
                        re.search(r'\b0\s*<=\s*' + re.escape(left_expr) + r'\b', line)
                    ):
                        continue

                    # A relational comparison of addresses (``p + n < q``, ``*p < n``)
                    # is pointer provenance, not integer signedness. Judge the whole
                    # operand expression, not just the identifier next to the operator.
                    left_text = self._extend_left(line, m.start(1)) + m.group(1)
                    right_text = m.group(3) + self._extend_right(line, m.end(3))
                    if self._expression_has_pointer(left_text, fn, ast_ctx) or self._expression_has_pointer(right_text, fn, ast_ctx):
                        continue

                    left_signedness = self._get_var_signedness(
                        left_expr, fn, ast_ctx,
                        dereferenced=self._is_dereferenced(line, m.start(1), m.end(1)),
                    )

                    if right_expr.startswith("-") and right_expr[1:].isdigit():
                        if left_signedness is True:
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                            add_issue(
                                line_no, snippet,
                                f"Signed/Unsigned Comparison: comparing unsigned operand '{left_expr}' with negative literal '{right_expr}' causes implicit promotion and logic errors.",
                                col=m.start() + 1
                            )
                        continue

                    right_signedness = self._get_var_signedness(right_expr, fn, ast_ctx)

                    if left_signedness is not None and right_signedness is not None:
                        if left_signedness != right_signedness:
                            signed_op = left_expr if left_signedness is False else right_expr
                            unsigned_op = left_expr if left_signedness is True else right_expr
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                            add_issue(
                                line_no, snippet,
                                f"Signed/Unsigned Comparison: comparing signed operand '{signed_op}' with unsigned operand '{unsigned_op}' causes implicit promotion and potential logic errors.",
                                col=m.start() + 1
                            )

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        target_line = masked_line_content or line_content

        m = re.search(
            r'\bfor\s*\(\s*(size_t|uint\w+_t|unsigned(?:\s+int)?)\s+([a-zA-Z_]\w*)\s*=\s*([^;]+);\s*\2\s*>=\s*0\s*;\s*([^)]+)\)',
            target_line
        )
        if m:
            var_type = m.group(1)
            var_name = m.group(2)
            init_expr = m.group(3).strip()
            step_expr = m.group(4).strip()
            is_decrement = '--' in step_expr or '-=' in step_expr or f'{var_name} -' in step_expr
            if is_decrement:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Infinite Loop Risk: unsigned loop variable '{var_name}' compared with '{var_name} >= 0' will always evaluate to true as unsigned types cannot be negative.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"for ({var_type} {var_name} = {init_expr}; {var_name} > 0; {var_name}--)"
                ))

        m = re.search(
            r'\bfor\s*\(\s*int\s+([a-zA-Z_]\w*)\s*=\s*([a-zA-Z_]\w*)\s*;\s*\1\s*>=\s*0\s*;\s*([^)]+)\)',
            target_line
        )
        if m:
            i_var = m.group(1)
            len_var = m.group(2)
            step_expr = m.group(3).strip()
            is_decrement = '--' in step_expr or '-=' in step_expr or f'{i_var} -' in step_expr
            if is_decrement and re.search(rf'\b(?:size_t|uint\w+_t|unsigned)\s+{re.escape(len_var)}\b', full_code):
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Loop Bound Mismatch: signed loop counter '{i_var}' initialized from unsigned bound '{len_var}'. If '{len_var}' exceeds INT_MAX, initialization wraps to negative.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"for (size_t {i_var} = {len_var}; {i_var} > 0; {i_var}--)"
                ))

        return issues
