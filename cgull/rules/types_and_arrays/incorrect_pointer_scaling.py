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
class IncorrectPointerScalingRule(BaseRule):
    rule_id = "CGULL-040"
    name = "Incorrect Pointer Scaling"
    impact = Severity.HIGH
    category = RuleCategory.ARITHMETIC
    description = "Detect pointer arithmetic where the offset is multiplied by sizeof(). In C, pointer arithmetic is automatically scaled by the size of the pointed-to type, so explicitly multiplying the offset by sizeof() leads to double scaling and out-of-bounds access."
    implementation_method = "AST traversal to find pointer arithmetic operations involving sizeof()"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-468"
    remediation_suggestion = "Remove the explicit sizeof() multiplication in the pointer offset calculation. C automatically scales pointer arithmetic."
    sample_vulnerable_code = "int *ptr = malloc(10 * sizeof(int));\nint *offset_ptr = ptr + (5 * sizeof(int)); // Double scaling!"
    sample_remediated_code = "int *ptr = malloc(10 * sizeof(int));\nint *offset_ptr = ptr + 5;"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return issues

        from ...cfg import find_function_def, _PRELUDE_LINE_COUNT
        from pycparser import c_ast
        from ...ast_analyzer import _format_pycparser_expr

        def is_byte_ptr(type_name: str, name: str = "") -> bool:
            # Check for double pointers (e.g., char **) which are scaled by sizeof(char*)
            full_decl = f"{type_name} {name}".strip()
            if full_decl.count('*') > 1:
                return False

            tn = type_name.strip()
            # Match strictly byte types: char, unsigned char, signed char, int8_t, uint8_t, void
            # Do not match wchar_t, char16_t, char32_t
            if re.search(r'\b(?:unsigned\s+|signed\s+)?char\b', tn):
                return True
            if re.search(r'\b(?:u?int8_t)\b', tn):
                return True
            if re.search(r'\bvoid\b', tn):
                return True
            return False

        def is_pointer_type(node, fn) -> bool:
            if isinstance(node, c_ast.ID):
                var_name = node.name

                if fn and var_name in fn.variables:
                    var_obj = fn.variables[var_name]
                    if var_obj.is_pointer or getattr(var_obj, "is_array", False) or '*' in var_obj.type_name or '*' in var_obj.name:
                        if not is_byte_ptr(var_obj.type_name, var_obj.name):
                            return True

                if var_name in ast_ctx.global_variables:
                    var_obj = ast_ctx.global_variables[var_name]
                    if var_obj.is_pointer or getattr(var_obj, "is_array", False) or '*' in var_obj.type_name or '*' in var_obj.name:
                        if not is_byte_ptr(var_obj.type_name, var_obj.name):
                            return True

                if fn:
                    for param in fn.parameters:
                        if param.name == var_name and (param.is_pointer or getattr(param, "is_array", False) or '*' in param.type_name or '*' in param.name or '[' in param.type_name):
                            if not is_byte_ptr(param.type_name, param.name):
                                return True

            elif isinstance(node, c_ast.UnaryOp) and node.op == '&':
                return True

            elif isinstance(node, c_ast.Cast):
                type_str = _format_pycparser_expr(node.to_type)
                if '*' in type_str:
                    if not is_byte_ptr(type_str):
                        return True

            return False

        def contains_sizeof(node) -> bool:
            if isinstance(node, c_ast.UnaryOp) and node.op == 'sizeof':
                return True

            found = [False]
            class SizeofFinder(c_ast.NodeVisitor):
                def visit_UnaryOp(self, n):
                    if n.op == 'sizeof':
                        found[0] = True
                    self.generic_visit(n)

            SizeofFinder().visit(node)
            return found[0]

        for fn in ast_ctx.functions:
            funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
            if funcdef is None:
                continue

            class PointerMathVisitor(c_ast.NodeVisitor):
                def __init__(self, rule_instance):
                    self.rule = rule_instance
                    self.reported_lines = set()

                def visit_Assignment(self, node):
                    if node.op in ('+=', '-='):
                        left_is_ptr = is_pointer_type(node.lvalue, fn)
                        if left_is_ptr and contains_sizeof(node.rvalue):
                            self._report(node)
                    self.generic_visit(node)

                def visit_BinaryOp(self, node):
                    if node.op in ('+', '-'):
                        left_is_ptr = is_pointer_type(node.left, fn)
                        right_is_ptr = is_pointer_type(node.right, fn)

                        if left_is_ptr and contains_sizeof(node.right):
                            self._report(node)
                        elif right_is_ptr and contains_sizeof(node.left):
                            self._report(node)

                    self.generic_visit(node)

                def _report(self, node):
                    line_no = (node.coord.line - _PRELUDE_LINE_COUNT) if node.coord else fn.start_line

                    if line_no in self.reported_lines:
                        return
                    self.reported_lines.add(line_no)

                    if line_no > 0 and line_no <= len(ast_ctx.source_lines):
                        code_snippet = ast_ctx.source_lines[line_no - 1].strip()
                    else:
                        code_snippet = _format_pycparser_expr(node)

                    issues.append(self.rule.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=code_snippet,
                        message="Incorrect pointer scaling: explicit sizeof() used in pointer arithmetic. C automatically scales by the size of the pointed-to type.",
                        column_number=getattr(node.coord, 'column', 1) if node.coord else 1,
                        engine="AST",
                        fix_type=FixType.MANUAL_REVIEW,
                    ))

            PointerMathVisitor(self).visit(funcdef)

        return issues
