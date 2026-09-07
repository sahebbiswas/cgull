"""Report definite pointer formation/access violations from shared range facts."""

from ..base import BaseRule
from ...semantic_models import SemanticModelRegistry
from ...ast_analyzer import _map_line
from ...cfg import _PRELUDE_LINE_COUNT
from ...models import AnalysisEngine, FixType, RuleCategory, Severity


class PointerRangeBoundsRule(BaseRule):
    rule_id = "CGULL-050"
    name = "Pointer Outside Object Bounds"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect pointer derivations and accesses provably outside the originating object."
    implementation_method = "Shared intraprocedural pointer origin, byte offset, and object extent facts"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-823"
    remediation_suggestion = "Keep pointer derivations within the object or its one-past address; access only complete elements inside the object."
    sample_vulnerable_code = "int a[10]; int *p = a + 3; int *q = p - 4;"
    sample_remediated_code = "int a[10]; int *p = a + 3; int *q = p - 3;"
    analysis_engine = AnalysisEngine.AST

    def set_semantic_models(self, registry):
        if isinstance(registry, SemanticModelRegistry):
            self._semantic_models = registry

    def scan_ast(self, file_path, ast_ctx):
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return []
        analysis = self.get_analysis_session(ast_ctx).pointer_range_analysis
        issues = []
        seen = set()
        for result in analysis.function_results.values():
            for event in result.events:
                fact = event.fact
                if event.access_width is None or not fact.definitely_outside(event.access_width):
                    continue
                coord = getattr(event.node, "coord", None)
                line = _map_line(max(1, (getattr(coord, "line", 0) or 0) - _PRELUDE_LINE_COUNT), ast_ctx.line_map)
                column = getattr(coord, "column", 1) or 1
                cwe = ("CWE-787" if event.write else "CWE-125") if event.access_width else "CWE-823"
                key = (line, column, cwe)
                if key in seen:
                    continue
                seen.add(key)
                action = "Write" if event.write else "Read" if event.access_width else "Pointer formation"
                offset = str(fact.offset.lower) if fact.offset.is_exact else f"[{fact.offset.lower}, {fact.offset.upper}]"
                issue = self.create_issue(
                    file_path=file_path, line_number=line, column_number=column,
                    code_snippet=ast_ctx.source_lines[line - 1].strip() if 0 < line <= len(ast_ctx.source_lines) else "",
                    message=f"{action} at byte offset {offset} is outside object '{fact.origin}' ({fact.object_extent} bytes)." + (f" Access width: {event.access_width} bytes." if event.access_width else ""),
                    engine="AST", fix_type=FixType.MANUAL_REVIEW,
                )
                issue.cwe_id = cwe
                issues.append(issue)
        return issues
