"""Diagnose address arithmetic that invalidates a range comparison."""
from .pointer_range_bounds import PointerRangeBoundsRule
from ...ast_analyzer import _map_line
from ...cfg import _PRELUDE_LINE_COUNT
from ...models import FixType


class PointerEndpointWraparoundRule(PointerRangeBoundsRule):
    rule_id = "CGULL-052"
    name = "Unsafe Pointer Range Endpoint"
    description = "Detect range checks relying on unproven non-wrapping address arithmetic."
    cwe_id = "CWE-190"
    chances_of_false_positives = "Medium"
    remediation_suggestion = "Prove endpoint ordering, then compare the length with the remaining distance before constructing the endpoint."
    sample_vulnerable_code = "return p + len <= end;"
    sample_remediated_code = "return p <= end && len <= (size_t)(end - p);"

    def scan_ast(self, file_path, ast_ctx):
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return []
        from ...cfg.pointer_endpoint_safety import key

        issues, seen = [], set()
        for result in self.get_analysis_session(ast_ctx).pointer_range_analysis.function_results.values():
            for check, expression in result.endpoint_checks:
                coord = check.coord
                line = _map_line(max(1, coord.line - _PRELUDE_LINE_COUNT), ast_ctx.line_map)
                column = coord.column or 1
                identity = (line, column, key(expression))
                if identity in seen:
                    continue
                seen.add(identity)
                issues.append(self.create_issue(
                    file_path=file_path, line_number=line, column_number=column,
                    code_snippet=ast_ctx.source_lines[line-1].strip() if 0 < line <= len(ast_ctx.source_lines) else "",
                    message=f"Pointer range check uses '{key(expression)}' without proving the address arithmetic cannot wrap or underflow; this comparison cannot reliably establish interval containment.",
                    engine="AST", fix_type=FixType.MANUAL_REVIEW,
                ))
        return issues
