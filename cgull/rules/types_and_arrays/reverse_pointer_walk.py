"""Report potential reverse access below a caller-visible base pointer."""
from .pointer_range_bounds import PointerRangeBoundsRule
from ...ast_analyzer import _map_line
from ...cfg import _PRELUDE_LINE_COUNT
from ...models import FixType


class ReversePointerWalkRule(PointerRangeBoundsRule):
    rule_id = "CGULL-056"
    name = "Unguarded Reverse Pointer Walk"
    description = "Detect reverse accesses that may cross an explicitly derived pointer's logical lower bound."
    implementation_method = "Shared AST pointer analysis with loop widening and ordered expression evaluation"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-125"
    remediation_suggestion = "Check the cursor against its base before decrementing and dereferencing it."
    sample_vulnerable_code = "char *p = base; use(*--p);"
    sample_remediated_code = "char *p = base; if (p > base) use(*--p);"

    def scan_ast(self, file_path, ast_ctx):
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return []
        issues = []
        for result in self.get_analysis_session(ast_ctx).pointer_range_analysis.function_results.values():
            for event in result.reverse_accesses:
                coord = event.node.coord
                line = _map_line(max(1, (getattr(coord, "line", 0) or 0) - _PRELUDE_LINE_COUNT), ast_ctx.line_map)
                issue = self.create_issue(
                    file_path=file_path, line_number=line,
                    column_number=getattr(coord, "column", 1) or 1,
                    code_snippet=ast_ctx.source_lines[line - 1].strip() if 0 < line <= len(ast_ctx.source_lines) else "",
                    message=f"Reverse {'write' if event.write else 'read'} may access before logical base '{event.origin}'. Guard the lower bound before the reverse access.",
                    engine="AST", fix_type=FixType.MANUAL_REVIEW,
                )
                issue.cwe_id = "CWE-787" if event.write else "CWE-125"
                issues.append(issue)
        return issues
