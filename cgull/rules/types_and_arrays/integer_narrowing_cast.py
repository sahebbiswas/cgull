"""Detect explicit integer casts that reduce the value width."""

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
    name = "Explicit Integer Narrowing Cast"
    impact = Severity.MEDIUM
    category = RuleCategory.ARITHMETIC
    description = "Detect explicit C-style casts that convert an integer expression to a narrower integer type, which can truncate significant bits."
    implementation_method = "AST traversal of pycparser Cast nodes with shared integer type-width comparison"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-197"
    remediation_suggestion = "Validate that the source value is representable in the destination type before narrowing, or retain a sufficiently wide integer type."
    sample_vulnerable_code = "uint32_t wide = read_value();\nuint8_t narrow = (uint8_t)wide;"
    sample_remediated_code = "uint32_t wide = read_value();\nif (wide <= UINT8_MAX) { uint8_t narrow = (uint8_t)wide; }"
    analysis_engine = AnalysisEngine.AST

    @staticmethod
    def _source_type(ast_ctx: CASTContext, node, fn) -> Optional[str]:
        return ast_ctx.infer_expr_type(node, fn)

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return []

        from pycparser import c_ast

        issues: List[Issue] = []

        for fn in ast_ctx.functions:
            funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
            if funcdef is None:
                continue

            rule = self

            class CastVisitor(c_ast.NodeVisitor):
                def visit_Cast(self, node):
                    destination_type = _format_pycparser_expr(node.to_type)
                    source_type = rule._source_type(ast_ctx, node.expr, fn)

                    if (
                        source_type
                        and is_integer_narrowing_conversion(source_type, destination_type, ast_ctx) is True
                    ):
                        source_width = get_integer_type_byte_size(source_type, ast_ctx)
                        destination_width = get_integer_type_byte_size(destination_type, ast_ctx)
                        raw_line = getattr(getattr(node, "coord", None), "line", 0) or 0
                        expanded_line = max(1, raw_line - _PRELUDE_LINE_COUNT) if raw_line else fn.start_line_exp
                        line_no = _map_line(expanded_line, ast_ctx.line_map)
                        if 0 < line_no <= len(ast_ctx.source_lines):
                            snippet = ast_ctx.source_lines[line_no - 1].strip()
                        else:
                            snippet = _format_pycparser_expr(node)
                        issues.append(rule.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=(
                                f"Explicit integer cast narrows '{source_type}' ({source_width * 8}-bit) "
                                f"to '{destination_type}' ({destination_width * 8}-bit), which may truncate the value."
                            ),
                            column_number=getattr(getattr(node, "coord", None), "column", 1) or 1,
                            engine="AST",
                            fix_type=FixType.MANUAL_REVIEW,
                        ))

                    self.generic_visit(node)

            CastVisitor().visit(funcdef)

        return issues
