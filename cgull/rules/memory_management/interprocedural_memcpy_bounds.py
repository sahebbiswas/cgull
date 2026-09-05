"""Interprocedural CGULL-044 memory-copy bounds analysis."""

from __future__ import annotations

from typing import List

from ...cfg.size_facts import SizeSafety
from ...models import Confidence, FixType, Issue
from .helpers import _source_snippet
from .memcpy_struct_member_overflow import (
    MemcpyStructMemberOverflowRule as _LegacyMemcpyStructMemberOverflowRule,
)


class MemcpyStructMemberOverflowRule(_LegacyMemcpyStructMemberOverflowRule):
    """Use shared bounded size facts before falling back to legacy local reasoning."""

    implementation_method = "Interprocedural size/extent facts with AST/CFG fallback"

    @staticmethod
    def _informative(call_fact) -> bool:
        """Only interprocedurally review UNKNOWN when destination capacity propagated.

        A known size alone is insufficient because the legacy rule may still prove
        a local struct-member capacity that the bounded size domain intentionally
        does not reconstruct from every legacy AST shape.
        """
        return (
            len(call_fact.extents) > 0
            and len(call_fact.sizes) > 2
            and not call_fact.extents[0].is_unknown
        )

    @staticmethod
    def _fact_text(fact) -> str:
        if fact.is_exact:
            return str(fact.exact_value)
        if fact.lower is not None and fact.upper is not None:
            return f"{fact.lower}..{fact.upper}"
        if fact.lower is not None:
            return f">={fact.lower}"
        if fact.upper is not None:
            return f"<={fact.upper}"
        return "unknown"

    def _interprocedural_issue(self, file_path: str, ast_ctx, call_fact, safety: SizeSafety) -> Issue:
        size = call_fact.sizes[2]
        capacity = call_fact.extents[0]
        snippet = _source_snippet(ast_ctx, call_fact.line, f"{call_fact.callee}(...)")
        flow = f"{call_fact.caller} -> {call_fact.callee}"
        if safety is SizeSafety.UNSAFE:
            message = (
                f"Buffer Overflow in '{call_fact.callee}': propagated size "
                f"({self._fact_text(size)} bytes) exceeds propagated destination "
                f"capacity ({self._fact_text(capacity)} bytes). Interprocedural "
                f"evidence: {flow}. Provable out-of-bounds write."
            )
        else:
            message = (
                f"Potentially Unchecked Buffer Overflow in '{call_fact.callee}': "
                f"propagated size ({self._fact_text(size)} bytes) and destination "
                f"capacity ({self._fact_text(capacity)} bytes) do not prove the copy "
                f"safe. Interprocedural evidence: {flow}."
            )
        issue = self.create_issue(
            file_path=file_path,
            line_number=max(1, call_fact.line),
            code_snippet=snippet,
            message=message,
            column_number=max(1, call_fact.column),
            engine="Interprocedural",
            fix_type=FixType.SUGGESTED_FIX,
            suggested_fix_replacement=(
                "Gate the requested size against the destination capacity before "
                f"calling {call_fact.callee}()."
            ),
        )
        if safety is SizeSafety.UNKNOWN or capacity.degradations or size.degradations:
            issue.confidence = Confidence.LIMITED
        return issue

    def scan_ast(self, file_path: str, ast_ctx) -> List[Issue]:
        legacy = super().scan_ast(file_path, ast_ctx)
        if not getattr(ast_ctx, "has_pycparser", False) or getattr(ast_ctx, "pycparser_ast", None) is None:
            return legacy

        size_result = self.get_analysis_session(ast_ctx).queries.size_facts()
        issues: List[Issue] = []
        handled = set()

        for call_fact in size_result.calls:
            if call_fact.callee not in self.TARGET_FUNCS or len(call_fact.extents) <= 0 or len(call_fact.sizes) <= 2:
                continue
            safety = call_fact.classify(buffer_arg=0, size_arg=2)
            site = (call_fact.line, call_fact.callee)

            if safety is SizeSafety.SAFE:
                handled.add(site)
                continue
            if safety is SizeSafety.UNSAFE or self._informative(call_fact):
                handled.add(site)
                issues.append(self._interprocedural_issue(file_path, ast_ctx, call_fact, safety))

        for issue in legacy:
            if any(
                issue.line_number == line and f"'{callee}'" in issue.message
                for line, callee in handled
            ):
                continue
            issues.append(issue)

        return sorted(issues, key=lambda issue: (issue.line_number, issue.column_number, issue.message))
