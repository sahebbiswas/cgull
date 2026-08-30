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
class PointerSubtractionSizeRule(BaseRule):
    rule_id = "CGULL-046"
    name = "Unscaled Pointer Subtraction in Size Argument"
    impact = Severity.HIGH
    category = RuleCategory.ARITHMETIC
    description = "Detect pointer subtraction used directly as a byte-size argument without scaling (e.g. multiplying by sizeof). Pointer subtraction in C yields the number of elements, not the number of bytes."
    implementation_method = "AST traversal to find pointer arithmetic operations passed as size arguments"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-469"
    remediation_suggestion = "Scale pointer subtraction by the size of the element type, or cast pointers to char* before subtracting."
    sample_vulnerable_code = "int *p1, *p2;\nmemcpy(dest, p1, p2 - p1); // p2 - p1 is number of ints, not bytes!"
    sample_remediated_code = "int *p1, *p2;\nmemcpy(dest, p1, (p2 - p1) * sizeof(int));"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return issues

        from pycparser import c_ast
        from ...ast_analyzer import _format_pycparser_expr
        from ...cfg import find_function_def

        def is_byte_ptr(type_name: str, name: str = "") -> bool:
            import re
            clean_tag = re.sub(r'^(?:const|volatile|struct|union)\s+', '', type_name.strip()).split('[')[0].replace('*', '').strip()
            if clean_tag and clean_tag in ast_ctx.typedef_shapes:
                from ...ast_analyzer import resolve_typedef_shape
                shape = resolve_typedef_shape(clean_tag, ast_ctx.typedef_shapes)
                tn = type_name.replace(clean_tag, shape.target).lower()
                if shape.is_pointer:
                    tn += "*"
            else:
                tn = type_name.lower()

            if tn.count('*') + name.count('*') > 1:
                return False
            for byte_t in ('char', 'int8_t', 'uint8_t', 'byte'):
                if re.search(r'\b' + re.escape(byte_t) + r'\b', tn):
                    return True
            if re.search(r'\bvoid\b', tn):
                return True
            return False

        target_funcs_indices = {
            "memcpy": 2, "memmove": 2, "memset": 2, "memcmp": 2,
            "malloc": 0, "valloc": 0, "mallocx": 0,
            "calloc": 0, # and 1, handled specially below
            "realloc": 1, "reallocf": 1,
            "strncpy": 2, "strncat": 2, "strncmp": 2,
            "snprintf": 1, "vsnprintf": 1,
            "bcopy": 2, "bzero": 1,
            "fgets": 1,
            "read": 2, "write": 2, "pread": 2, "pwrite": 2,
            "recv": 2, "recvfrom": 2, "send": 2, "sendto": 2
        }

        def _is_unscaled_pointer_subtraction(node, fn) -> bool:
            def is_pointer_type(n) -> bool:
                type_str = ast_ctx.infer_expr_type(n, fn)
                if type_str:
                    if '*' in type_str or '[' in type_str:
                        if not is_byte_ptr(type_str):
                            return True

                    clean_tag = re.sub(r'^(?:const|volatile|struct|union)\s+', '', type_str.strip()).split('[')[0].strip()
                    if clean_tag in ast_ctx.typedef_shapes:
                        from ...ast_analyzer import resolve_typedef_shape
                        shape = resolve_typedef_shape(clean_tag, ast_ctx.typedef_shapes)
                        if shape.is_pointer or shape.is_array:
                            if not is_byte_ptr(shape.target + "*"):
                                return True
                    return False

                if isinstance(n, c_ast.ID):
                    var_name = n.name
                    if fn and var_name in fn.variables:
                        var_obj = fn.variables[var_name]
                        if var_obj.is_pointer or getattr(var_obj, "is_array", False) or '*' in var_obj.type_name or '*' in var_obj.name:
                            if not is_byte_ptr(var_obj.type_name, var_obj.name):
                                return True
                    elif fn and any(p.name == var_name for p in fn.parameters):
                        for param in fn.parameters:
                            if param.name == var_name:
                                if param.is_pointer or getattr(param, "is_array", False) or '*' in param.type_name or '*' in param.name or '[' in param.type_name:
                                    if not is_byte_ptr(param.type_name, param.name):
                                        return True
                                break
                    elif var_name in ast_ctx.global_variables:
                        var_obj = ast_ctx.global_variables[var_name]
                        if var_obj.is_pointer or getattr(var_obj, "is_array", False) or '*' in var_obj.type_name or '*' in var_obj.name:
                            if not is_byte_ptr(var_obj.type_name, var_obj.name):
                                return True
                elif isinstance(n, c_ast.Cast):
                    type_str = _format_pycparser_expr(n.to_type)
                    if '*' in type_str:
                        if not is_byte_ptr(type_str):
                            return True
                return False

            if isinstance(node, c_ast.BinaryOp):
                if node.op == '-':
                    left_is_ptr = is_pointer_type(node.left)
                    right_is_ptr = is_pointer_type(node.right)
                    if left_is_ptr and right_is_ptr:
                        return True

                if node.op == '*':
                    def is_sizeof(n):
                        return isinstance(n, c_ast.UnaryOp) and n.op == 'sizeof'
                    if is_sizeof(node.left) or is_sizeof(node.right):
                        return False

                return _is_unscaled_pointer_subtraction(node.left, fn) or _is_unscaled_pointer_subtraction(node.right, fn)

            elif isinstance(node, c_ast.Cast):
                 return _is_unscaled_pointer_subtraction(node.expr, fn)

            return False

        for fn in ast_ctx.functions:
            funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
            if funcdef is None:
                continue

            reported_lines = set()

            class SizeArgVisitor(c_ast.NodeVisitor):
                def __init__(self, rule_instance):
                    self.rule = rule_instance

                def visit_FuncCall(self, node):
                    if isinstance(node.name, c_ast.ID) and node.name.name in target_funcs_indices:
                        func_name = node.name.name
                        idx1 = target_funcs_indices[func_name]
                        indices = [idx1]
                        if func_name == "calloc":
                             indices.append(1)

                        if node.args and isinstance(node.args, c_ast.ExprList):
                            for idx in indices:
                                if len(node.args.exprs) > idx:
                                    arg_expr = node.args.exprs[idx]
                                    if _is_unscaled_pointer_subtraction(arg_expr, fn):
                                        from ...cfg import _PRELUDE_LINE_COUNT
                                        line_no = (node.coord.line - _PRELUDE_LINE_COUNT) if node.coord else fn.start_line
                                        if line_no not in reported_lines:
                                            reported_lines.add(line_no)
                                            snippet = ast_ctx.source_lines[line_no - 1].strip() if 0 < line_no <= len(ast_ctx.source_lines) else _format_pycparser_expr(node)
                                            issues.append(self.rule.create_issue(
                                                file_path=file_path,
                                                line_number=line_no,
                                                code_snippet=snippet,
                                                message=f"Unscaled pointer subtraction used as a byte-size argument to '{func_name}'. Pointer subtraction yields the number of elements, not bytes.",
                                                column_number=getattr(node.coord, 'column', 1) if node.coord else 1,
                                                engine="AST",
                                                fix_type=FixType.MANUAL_REVIEW,
                                            ))
                    self.generic_visit(node)

            SizeArgVisitor(self).visit(funcdef)

        return issues
