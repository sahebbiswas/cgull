"""Detect explicit and implicit integer conversions that lose width or change signedness unsafely."""

from typing import List, Optional

from ..base import BaseRule
from ...ast_analyzer import (
    CASTContext,
    _format_pycparser_expr,
    _map_line,
    build_direct_call_signature_index,
    get_integer_type_byte_size,
    is_integer_narrowing_conversion,
)
from ...ast_analyzer.integer_types import _resolved_scalar_type
from ...cfg import _PRELUDE_LINE_COUNT, analyze_integer_ranges, find_function_def, integer_type_range
from ...models import AnalysisEngine, Confidence, FixType, Issue, RuleCategory, Severity


class IntegerNarrowingCastRule(BaseRule):
    rule_id = "CGULL-049"
    name = "Unsafe Integer Conversion"
    impact = Severity.MEDIUM
    category = RuleCategory.ARITHMETIC
    description = "Detect unexpected sign extension from narrow signed sources (CWE-194), integer truncation (CWE-197), negative signed-to-unsigned conversion (CWE-195), and out-of-range unsigned-to-signed conversion (CWE-196) in casts, initialization, assignment, and direct argument binding."
    implementation_method = "AST conversion detection with CFG-backed integer range provenance and guard suppression"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low-Medium"
    cwe_id = "CWE-197"
    remediation_suggestion = "Validate that the source value is representable in the destination type before conversion, or retain an integer type with sufficient range and appropriate signedness."
    sample_vulnerable_code = "uint32_t wide = read_value();\nuint8_t narrow = wide;"
    sample_remediated_code = "uint32_t wide = read_value();\nif (wide <= UINT8_MAX) { uint8_t narrow = (uint8_t)wide; }"
    analysis_engine = AnalysisEngine.AST

    @staticmethod
    def _source_type(ast_ctx: CASTContext, node, fn) -> Optional[str]:
        inferred = ast_ctx.infer_expr_type(node, fn)
        if inferred:
            return inferred
        if type(node).__name__ == "Constant":
            if node.type == "char":
                return "int"
            return node.type if get_integer_type_byte_size(node.type, ast_ctx) is not None else None
        if type(node).__name__ == "UnaryOp" and node.op in {"+", "-", "~"}:
            operand = IntegerNarrowingCastRule._source_type(ast_ctx, node.expr, fn)
            width = get_integer_type_byte_size(operand, ast_ctx) if operand else None
            int_width = get_integer_type_byte_size("int", ast_ctx)
            return "int" if width is not None and width < int_width else operand
        return None

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

        for fn in ast_ctx.functions:
            funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
            if funcdef is None:
                continue
            range_analysis = analyze_integer_ranges(ast_ctx, fn.name)
            signature_index = build_direct_call_signature_index(ast_ctx, funcdef)
            rule = self

            class ConversionVisitor(c_ast.NodeVisitor):
                def _append_conversion(self, source_node, destination_type: Optional[str], node, kind: str):
                    if not destination_type:
                        return
                    source_type = rule._source_type(ast_ctx, source_node, fn)
                    if not source_type:
                        return
                    source_width = get_integer_type_byte_size(source_type, ast_ctx)
                    destination_width = get_integer_type_byte_size(destination_type, ast_ctx)
                    int_width = get_integer_type_byte_size("int", ast_ctx)
                    if source_width is None or destination_width is None or int_width is None:
                        return
                    source_range = integer_type_range(source_type, ast_ctx)
                    destination_range = integer_type_range(destination_type, ast_ctx)
                    signedness_change = (
                        source_range is not None and destination_range is not None
                        and (source_range.lower < 0) != (destination_range.lower < 0)
                    )
                    plain_char = _resolved_scalar_type(source_type, ast_ctx) == "char"
                    sign_extension = (
                        source_width < int_width and source_width < destination_width
                        and destination_range is not None
                        and (plain_char or source_range is not None and source_range.lower < 0)
                    )
                    narrowing = is_integer_narrowing_conversion(source_type, destination_type, ast_ctx)
                    if not sign_extension and not signedness_change and narrowing is not True:
                        return
                    if sign_extension:
                        value_range = (
                            range_analysis.range_for_expression(source_node, node)
                            if range_analysis is not None else None
                        )
                        if value_range is not None and value_range.lower is not None and value_range.lower >= 0:
                            return
                    else:
                        if source_range is not None and destination_range is not None and source_range.fits_within(destination_range):
                            return
                        if range_analysis is not None and range_analysis.proves_expression_fits(
                            source_node, destination_type, node
                        ):
                            return

                    line_no = rule._line_for_node(ast_ctx, node, fn)
                    if 0 < line_no <= len(ast_ctx.source_lines):
                        snippet = ast_ctx.source_lines[line_no - 1].strip()
                    else:
                        snippet = _format_pycparser_expr(node)
                    if sign_extension:
                        cwe = "CWE-194"
                        risk = (
                            "may sign-extend if plain char is signed on the target; its signedness is unknown"
                            if plain_char else "may sign-extend a negative byte-like value"
                        )
                        message = (
                            f"{kind} widens '{source_type}' ({source_width * 8}-bit) "
                            f"to '{destination_type}' ({destination_width * 8}-bit) and {risk}. "
                            "Review whether the source represents unsigned byte or protocol data."
                        )
                    elif signedness_change:
                        cwe = "CWE-195" if source_range.lower < 0 else "CWE-196"
                        risk = (
                            "may convert a negative value to unsigned"
                            if cwe == "CWE-195" else "may exceed the signed destination maximum"
                        )
                        message = f"{kind} converts '{source_type}' to '{destination_type}', which {risk}."
                    else:
                        cwe = "CWE-197"
                        message = (
                            f"{kind} narrows '{source_type}' ({source_width * 8}-bit) "
                            f"to '{destination_type}' ({destination_width * 8}-bit), which may truncate the value."
                        )
                    issue = rule.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        message=message,
                        column_number=getattr(getattr(node, "coord", None), "column", 1) or 1,
                        engine="AST",
                        fix_type=FixType.MANUAL_REVIEW,
                    )
                    issue.cwe_id = cwe
                    if sign_extension:
                        issue.remediation = (
                            "If the value represents byte or protocol data, use an unsigned source type "
                            "or explicitly convert through the matching unsigned narrow type before widening. "
                            "Otherwise validate nonnegativity or review whether signed widening is intentional."
                        )
                        if plain_char:
                            issue.confidence = Confidence.LIMITED
                    issues.append(issue)

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
                        signature = signature_index.resolve(node)
                        arguments = getattr(node.args, "exprs", None) or []
                        if signature is not None and signature.resolved and signature.has_prototype:
                            for index, (argument, parameter) in enumerate(
                                zip(arguments, signature.parameters), start=1
                            ):
                                if parameter.is_pointer or parameter.is_array:
                                    continue
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
