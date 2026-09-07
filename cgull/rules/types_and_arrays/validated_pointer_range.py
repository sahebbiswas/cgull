"""Report memory uses that exceed a successful range validator's proof."""

from .pointer_range_bounds import PointerRangeBoundsRule
from ...ast_analyzer import _map_line
from ...cfg import _PRELUDE_LINE_COUNT
from ...models import FixType


class ValidatedPointerRangeRule(PointerRangeBoundsRule):
    rule_id = "CGULL-051"
    name = "Access Outside Validated Pointer Range"
    description = "Detect accesses not covered by a successfully validated pointer interval."
    implementation_method = "Shared pointer facts and semantic validator success contracts"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-119"
    remediation_suggestion = "Validate the complete accessed interval or establish the enclosing object's bounds."
    sample_vulnerable_code = "if (!valid(p, 16)) return; use(*(int *)(p + 14));"
    sample_remediated_code = "if (!valid(p, 16)) return; use(*(int *)(p + 4));"

    def scan_ast(self, file_path, ast_ctx):
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return []
        issues, seen = [], set()
        for result in self.get_analysis_session(ast_ctx).pointer_range_analysis.function_results.values():
            for event in result.events:
                fact, width = event.fact, event.access_width
                if not event.is_access or not fact.proven_intervals:
                    continue
                if width is not None and fact.definitely_outside(width):
                    continue  # CGULL-050 provides the stronger object-bound diagnostic.
                known = not fact.offset.is_unknown and width is not None
                if known and fact.object_extent is not None and fact.offset.lower >= 0 and fact.offset.upper + width <= fact.object_extent:
                    continue
                intervals = []
                for lower, upper in sorted(fact.proven_intervals):
                    if intervals and lower <= intervals[-1][1]:
                        intervals[-1] = (intervals[-1][0], max(upper, intervals[-1][1]))
                    else:
                        intervals.append((lower, upper))
                if known and any(fact.offset.lower >= lower and fact.offset.upper + width <= upper for lower, upper in intervals):
                    continue
                detail = "cannot be proven to fit within the validated range (unknown offset or access width)"
                if known:
                    if fact.offset.upper < intervals[0][0]:
                        detail = "accesses bytes before the validated range"
                    elif fact.offset.lower + width > intervals[-1][1]:
                        detail = "accesses bytes beyond the validated range"
                    else:
                        detail = "may access bytes outside the validated range"
                coord = getattr(event.node, "coord", None)
                line = _map_line(max(1, (getattr(coord, "line", 0) or 0) - _PRELUDE_LINE_COUNT), ast_ctx.line_map)
                column = getattr(coord, "column", 1) or 1
                key = (line, column)
                if key in seen:
                    continue
                seen.add(key)
                issues.append(self.create_issue(
                    file_path=file_path, line_number=line, column_number=column,
                    code_snippet=ast_ctx.source_lines[line - 1].strip() if 0 < line <= len(ast_ctx.source_lines) else "",
                    message=f"Pointer derived from '{fact.origin}' {detail}. Prior validation or enclosing guards prove byte intervals {intervals} relative to that origin; it does not establish accessible storage outside them.",
                    engine="AST", fix_type=FixType.MANUAL_REVIEW,
                ))
        return issues
