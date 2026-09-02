"""Constant-expression extensions for CGULL-007 array bounds checks."""

import re
from typing import Optional

from .array_index_out_of_bounds import ArrayIndexOutOfBoundsRule as _BaseArrayIndexOutOfBoundsRule
from ...models import FixType


class ArrayIndexOutOfBoundsRule(_BaseArrayIndexOutOfBoundsRule):
    """Extend CGULL-007 with AST evaluation of negative constant subscripts.

    pycparser represents ``-1`` as ``UnaryOp('-', Constant('1'))`` and folds
    parentheses into the expression tree, so string-to-int conversion misses
    both unary-negative and arithmetic constant expressions. This evaluator
    handles integer constants plus unary ``+``/``-`` and a conservative set of
    integer binary operators. Unsigned casts deliberately return unknown here
    so a wrapped value such as ``(unsigned)-1`` is not mislabeled as negative.
    Only negative values are added here; existing CGULL-007 logic remains
    authoritative for non-negative constant bounds.
    """

    @staticmethod
    def _cast_is_unsigned(node) -> bool:
        from pycparser import c_ast

        type_node = getattr(node, "to_type", None)
        if not isinstance(type_node, c_ast.Typename):
            return False
        type_decl = getattr(type_node, "type", None)
        while hasattr(type_decl, "type") and not isinstance(type_decl, c_ast.IdentifierType):
            type_decl = type_decl.type
        return isinstance(type_decl, c_ast.IdentifierType) and "unsigned" in type_decl.names

    @staticmethod
    def _constant_integer_value(node) -> Optional[int]:
        from pycparser import c_ast

        if isinstance(node, c_ast.Constant) and node.type == "int":
            token = re.sub(r"[uUlL]+$", "", str(node.value))
            try:
                return int(token, 0)
            except ValueError:
                return None

        if isinstance(node, c_ast.Cast):
            if ArrayIndexOutOfBoundsRule._cast_is_unsigned(node):
                return None
            return ArrayIndexOutOfBoundsRule._constant_integer_value(node.expr)

        if isinstance(node, c_ast.UnaryOp) and node.op in {"+", "-"}:
            value = ArrayIndexOutOfBoundsRule._constant_integer_value(node.expr)
            if value is None:
                return None
            return value if node.op == "+" else -value

        if isinstance(node, c_ast.BinaryOp):
            left = ArrayIndexOutOfBoundsRule._constant_integer_value(node.left)
            right = ArrayIndexOutOfBoundsRule._constant_integer_value(node.right)
            if left is None or right is None:
                return None

            try:
                if node.op == "+":
                    return left + right
                if node.op == "-":
                    return left - right
                if node.op == "*":
                    return left * right
                if node.op == "/" and right != 0:
                    return int(left / right)
                if node.op == "%" and right != 0:
                    quotient = int(left / right)
                    return left - quotient * right
                if node.op == "<<" and right >= 0:
                    return left << right
                if node.op == ">>" and right >= 0:
                    return left >> right
                if node.op == "&":
                    return left & right
                if node.op == "|":
                    return left | right
                if node.op == "^":
                    return left ^ right
            except (ArithmeticError, OverflowError):
                return None

        return None

    @staticmethod
    def _fixed_array_size(ast_ctx, fn, arr_name: str) -> Optional[int]:
        var_obj = fn.variables.get(arr_name) or ast_ctx.global_variables.get(arr_name)
        if not var_obj or not var_obj.array_size_expr:
            return None

        expr = var_obj.array_size_expr.strip()
        token = re.sub(r"[uUlL]+$", "", expr)
        try:
            value = int(token, 0)
        except ValueError:
            return None
        return value if value >= 0 else None

    def scan_ast(self, file_path, ast_ctx):
        issues = super().scan_ast(file_path, ast_ctx)
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return issues

        from pycparser import c_ast
        from ...ast_analyzer import _format_pycparser_expr
        from ...cfg import _PRELUDE_LINE_COUNT, find_function_def

        reported = set()

        for fn in ast_ctx.functions:
            funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
            if funcdef is None:
                continue

            rule = self

            class NegativeConstantVisitor(c_ast.NodeVisitor):
                def visit_ArrayRef(v_self, node):
                    value = rule._constant_integer_value(node.subscript)
                    if value is not None and value < 0 and isinstance(node.name, c_ast.ID):
                        arr_name = node.name.name
                        arr_size = rule._fixed_array_size(ast_ctx, fn, arr_name)
                        if arr_size is not None:
                            line_no = (
                                node.coord.line - _PRELUDE_LINE_COUNT
                                if node.coord
                                else fn.start_line
                            )
                            snippet = (
                                ast_ctx.source_lines[line_no - 1].strip()
                                if 0 < line_no <= len(ast_ctx.source_lines)
                                else f"{arr_name}[{_format_pycparser_expr(node.subscript)}]"
                            )
                            column = node.coord.column if node.coord else 1
                            key = (line_no, arr_name, value, column)
                            if key not in reported:
                                issues.append(rule.create_issue(
                                    file_path=file_path,
                                    line_number=line_no,
                                    code_snippet=snippet,
                                    message=(
                                        f"Static Array Out-of-Bounds: index [{value}] is below zero "
                                        f"for declared dimension of '{arr_name}[{arr_size}]'."
                                    ),
                                    column_number=column,
                                    engine="AST",
                                    fix_type=FixType.SUGGESTED_FIX,
                                    suggested_fix_replacement=f"{arr_name}[0]",
                                ))
                                reported.add(key)

                    v_self.generic_visit(node)

            NegativeConstantVisitor().visit(funcdef)

        return issues
