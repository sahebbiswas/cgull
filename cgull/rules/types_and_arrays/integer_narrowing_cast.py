"""Detect explicit and implicit integer conversions that reduce value width."""

from typing import List, Optional

from ..base import BaseRule
from ...ast_analyzer import (
    CASTContext,
    _format_pycparser_expr,
    _map_line,
    get_integer_type_byte_size,
    is_integer_narrowing_conversion,
)
from ...cfg import _PRELUDE_LINE_COUNT, find_function_def
from ...models import AnalysisEngine, FixType, Issue, RuleCategory, Severity


class IntegerNarrowingCastRule(BaseRule):
    rule_id = "CGULL-049"
    name = "Integer Narrowing Conversion"
    impact = Severity.MEDIUM
    category = RuleCategory.ARITHMETIC
    description = "Detect explicit casts and implicit assignments or argument binding that convert an integer expression to a narrower integer type, which can truncate significant bits."
    implementation_method = "AST traversal of casts, declarations, assignments, and direct calls with shared integer type-width comparison"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-197"
    remediation_suggestion = "Validate that the source value is representable in the destination type before narrowing, or retain a sufficiently wide integer type."
    sample_vulnerable_code = "uint32_t wide = read_value();\nuint8_t narrow = wide;"
    sample_remediated_code = "uint32_t wide = read_value();\nif (wide <= UINT8_MAX) { uint8_t narrow = (uint8_t)wide; }"
    analysis_engine = AnalysisEngine.AST

    @staticmethod
    def _source_type(ast_ctx: CASTContext, node, fn) -> Optional[str]:
        return ast_ctx.infer_expr_type(node, fn)

    @staticmethod
    def _destination_type_for_decl(ast_ctx: CASTContext, node, fn) -> Optional[str]:
        if not getattr(node, "name", None):
            return None
        variable = fn.variables.get(node.name)
        return variable.type_name if variable is not None else None

    @staticmethod
    def _line_for_node(ast_ctx: CASTContext, node, fn) -> int:
        raw_line = getattr(getattr(node, "coord", None), "line", 0) or 0
        expanded_line = max(1, raw_line - _PRELUDE_LINE_COUNT) if raw_line else fn.start_line_exp
        return _map_line(expanded_line, ast_ctx.line_map)

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return []

        from pycparser import c_ast

        issues: List[Issue] = []
        functions_by_name = {candidate.name: candidate for candidate in ast_ctx.functions}

        for fn in ast_ctx.functions:
            funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
            if funcdef is None:
                continue

            rule = self

            class ConversionVisitor(c_ast.NodeVisitor):
                def _append_conversion(self, source_node, destination_type: Optional[str], node, kind: str):
                    if not destination_type:
                        return
                    source_type = rule._source_type(ast_ctx, source_node, fn)
                    if not source_type or is_integer_narrowing_conversion(source_type, destination_type, ast_ctx) is not True:
                        return

                    source_width = get_integer_type_byte_size(source_type, ast_ctx)
                    destination_width = get_integer_type_byte_size(destination_type, ast_ctx)
                    if source_width is None or destination_width is None:
                        return

                    line_no = rule._line_for_node(ast_ctx, node, fn)
                    if 0 < line_no <= len(ast_ctx.source_lines):
                        snippet = ast_ctx.source_lines[line_no - 1].strip()
                    else:
                        snippet = _format_pycparser_expr(node)
                    issues.append(rule.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        message=(
                            f"{kind} narrows '{source_type}' ({source_width * 8}-bit) "
                            f"to '{destination_type}' ({destination_width * 8}-bit), which may truncate the value."
                        ),
                        column_number=getattr(getattr(node, "coord", None), "column", 1) or 1,
                        engine="AST",
                        fix_type=FixType.MANUAL_REVIEW,
                    ))

                def visit_Cast(self, node):
                    self._append_conversion(
                        node.expr,
                        _format_pycparser_expr(node.to_type),
                        node,
                        "Explicit integer cast",
                    )
                    self.generic_visit(node)

                def visit_Decl(self, node):
                    if node.init is not None:
                        self._append_conversion(
                            node.init,
                            rule._destination_type_for_decl(ast_ctx, node, fn),
                            node,
                            "Implicit declaration initialization",
                        )
                    self.generic_visit(node)

                def visit_Assignment(self, node):
                    if node.op == "=":
                        self._append_conversion(
                            node.rvalue,
                            ast_ctx.infer_expr_type(node.lvalue, fn),
                            node,
                            "Implicit assignment",
                        )
                    self.generic_visit(node)

                def visit_FuncCall(self, node):
                    if isinstance(node.name, c_ast.ID) and node.args is not None:
                        callee = functions_by_name.get(node.name.name)
                        arguments = getattr(node.args, "exprs", None) or []
                        if callee is not None:
                            for index, (argument, parameter) in enumerate(
                                zip(arguments, callee.parameters), start=1
                            ):
                                parameter_label = (
                                    f"parameter '{parameter.name}'"
                                    if parameter.name
                                    else f"parameter #{index}"
                                )
                                self._append_conversion(
                                    argument,
                                    parameter.type_name,
                                    argument,
                                    f"Implicit argument binding for {parameter_label}",
                                )
                    self.generic_visit(node)

            ConversionVisitor().visit(funcdef)

        return issues
