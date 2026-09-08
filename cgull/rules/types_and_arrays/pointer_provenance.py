"""Use shared pointer facts to report invalid provenance assumptions."""

from .pointer_range_bounds import PointerRangeBoundsRule
from ...ast_analyzer import _map_line
from ...cfg import _PRELUDE_LINE_COUNT
from ...models import FixType


class PointerProvenanceRule(PointerRangeBoundsRule):
    rule_id = 'CGULL-053'
    name = 'Unproven Pointer Provenance'
    description = 'Detect cross-object pointer subtraction and memory uses after provenance loss or unproven container recovery.'
    implementation_method = 'Shared pointer facts and interprocedural access requirements'
    chances_of_false_positives = 'Medium'
    cwe_id = 'CWE-823'
    remediation_suggestion = 'Preserve the original object relationship and prove containment before accessing the derived pointer.'
    sample_vulnerable_code = 'int a[8], b[8]; long d = &a[4] - &b[2];'
    sample_remediated_code = 'int a[8]; long d = &a[4] - &a[2];'

    def scan_ast(self, file_path, ast_ctx):
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return []
        issues, seen = [], set()
        for result in self.get_analysis_session(ast_ctx).pointer_range_analysis.function_results.values():
            for event in result.events:
                reasons = event.fact.degradations
                subtraction = 'CROSS_OBJECT_SUBTRACTION' in reasons
                if not subtraction and (not event.is_access or not reasons.intersection({'PROVENANCE_LOST', 'UNPROVEN_CONTAINER'})):
                    continue
                if event.access_width is not None and event.fact.definitely_outside(event.access_width):
                    continue  # The definite object-bounds diagnostic is stronger.
                coord = getattr(event.node, 'coord', None)
                line = _map_line(max(1, (getattr(coord, 'line', 0) or 0) - _PRELUDE_LINE_COUNT), ast_ctx.line_map)
                column = getattr(coord, 'column', 1) or 1
                if (line, column) in seen:
                    continue
                seen.add((line, column))
                message = ('Pointer subtraction uses pointers from distinct objects.' if subtraction else
                           'Memory access uses a recovered container without proof of the containing-object relationship.' if 'UNPROVEN_CONTAINER' in reasons else
                           'Memory access uses a pointer whose object provenance was lost in an unsupported, lossy, or misaligned transformation.')
                issue = self.create_issue(
                    file_path=file_path, line_number=line, column_number=column,
                    code_snippet=ast_ctx.source_lines[line - 1].strip() if 0 < line <= len(ast_ctx.source_lines) else '',
                    message=message + (f" Required by call to '{event.callee}'." if event.callee else ''),
                    engine='AST', fix_type=FixType.MANUAL_REVIEW,
                )
                issue.cwe_id = 'CWE-469' if subtraction else 'CWE-823'
                issues.append(issue)
        return issues
