"""Precise same-line call-site matching for CGULL-044."""

from __future__ import annotations

import re
from typing import Optional

from ..banned_functions import BannedFunctionsRule
from ...cfg.size_facts import SizeSafety
from .interprocedural_memcpy_bounds import (
    MemcpyStructMemberOverflowRule as _InterproceduralMemcpyStructMemberOverflowRule,
)


class MemcpyStructMemberOverflowRule(_InterproceduralMemcpyStructMemberOverflowRule):
    """Disambiguate sibling calls using the size fact's destination shape."""

    @classmethod
    def _destination_for_call(cls, ast_ctx, call_fact) -> Optional[str]:
        lines = getattr(ast_ctx, "source_lines", None) or (
            getattr(ast_ctx, "clean_source", "") or ""
        ).splitlines()
        source_line = cls._source_line(ast_ctx, call_fact)
        if not (0 < source_line <= len(lines)):
            return super()._destination_for_call(ast_ctx, call_fact)

        source_text = lines[source_line - 1]
        pattern = re.compile(rf"\b{re.escape(call_fact.callee)}\s*\(")
        destinations = []
        for match in pattern.finditer(source_text):
            args = BannedFunctionsRule._extract_call_args(
                source_text, match.end() - 1
            )
            if args:
                destinations.append(args[0].strip())

        if len(destinations) <= 1:
            return (
                destinations[0]
                if destinations
                else super()._destination_for_call(ast_ctx, call_fact)
            )

        extent = call_fact.extents[0] if call_fact.extents else None
        degradations = set(getattr(extent, "degradations", ()) or ())
        offset_degradations = {"ARRAY_ELEMENT_NOT_BUFFER", "POINTER_ARITHMETIC"}

        if degradations & offset_degradations:
            offset_destinations = [
                destination
                for destination in destinations
                if not cls._is_simple_destination(destination)
            ]
            if len(offset_destinations) == 1:
                return offset_destinations[0]

        if extent is not None and extent.is_exact:
            simple_destinations = [
                destination
                for destination in destinations
                if cls._is_simple_destination(destination)
            ]
            if len(simple_destinations) == 1:
                return simple_destinations[0]

        return super()._destination_for_call(ast_ctx, call_fact)

    def scan_ast(self, file_path: str, ast_ctx):
        """Recover locally provable offset overflows hidden by UNKNOWN size facts."""
        issues = super().scan_ast(file_path, ast_ctx)
        if not getattr(ast_ctx, "has_pycparser", False) or getattr(
            ast_ctx, "pycparser_ast", None
        ) is None:
            return issues

        size_result = self.get_analysis_session(ast_ctx).queries.size_facts()
        for call_fact in size_result.calls:
            if call_fact.callee not in self.TARGET_FUNCS:
                continue
            if len(call_fact.extents) <= 0 or len(call_fact.sizes) <= 2:
                continue
            if call_fact.classify(buffer_arg=0, size_arg=2) is not SizeSafety.UNKNOWN:
                continue

            destination = self._destination_for_call(ast_ctx, call_fact)
            if self._is_simple_destination(destination):
                continue
            residual_issue = self._residual_capacity_issue(
                file_path, ast_ctx, call_fact, destination
            )
            if residual_issue is not None:
                issues.append(residual_issue)

        return sorted(
            issues,
            key=lambda issue: (issue.line_number, issue.column_number, issue.message),
        )
