"""Precise same-line call-site matching for CGULL-044."""

from __future__ import annotations

import re
from typing import Optional

from ..banned_functions import BannedFunctionsRule
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
