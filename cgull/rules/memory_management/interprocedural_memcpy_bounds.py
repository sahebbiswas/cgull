"""Interprocedural CGULL-044 memory-copy bounds analysis."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ...ast_analyzer import _PRELUDE_LINE_COUNT, _map_line
from ...cfg.size_facts import SizeSafety
from ...models import Confidence, FixType, Issue
from ..banned_functions import BannedFunctionsRule
from .helpers import _source_snippet
from .memcpy_struct_member_overflow import (
    MemcpyStructMemberOverflowRule as _LegacyMemcpyStructMemberOverflowRule,
)


class MemcpyStructMemberOverflowRule(_LegacyMemcpyStructMemberOverflowRule):
    """Use shared bounded size facts before falling back to legacy local reasoning."""

    implementation_method = "Interprocedural size/extent facts with AST/CFG fallback"

    @staticmethod
    def _informative(call_fact) -> bool:
        """Only review UNKNOWN facts when destination capacity propagated."""
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

    @staticmethod
    def _normalize_destination(destination: Optional[str]) -> Optional[str]:
        if not destination:
            return None
        return re.sub(r"\s+", "", destination.strip())

    @staticmethod
    def _source_line(ast_ctx, call_fact) -> int:
        """Map a pycparser/prelude coordinate back to the original source line."""
        raw_line = int(getattr(call_fact, "line", 0) or 0)
        if raw_line <= 0:
            return 1
        expanded_line = max(1, raw_line - _PRELUDE_LINE_COUNT)
        return _map_line(expanded_line, getattr(ast_ctx, "line_map", None))

    @classmethod
    def _destination_for_call(cls, ast_ctx, call_fact) -> Optional[str]:
        """Recover the destination expression for one precise call site.

        The pycparser call coordinate identifies the callee token's physical
        column.  Prefer the source occurrence nearest that column so multiple
        sibling calls on the same line remain independent even when size-fact
        traversal order differs from source order.
        """
        lines = getattr(ast_ctx, "source_lines", None) or (
            getattr(ast_ctx, "clean_source", "") or ""
        ).splitlines()
        source_line = cls._source_line(ast_ctx, call_fact)
        if not (0 < source_line <= len(lines)):
            return None

        pattern = re.compile(rf"\b{re.escape(call_fact.callee)}\s*\(")
        expected = max(0, int(call_fact.column or 1) - 1)
        source_text = lines[source_line - 1]
        line_matches = list(pattern.finditer(source_text))
        if line_matches:
            match = min(line_matches, key=lambda item: abs(item.start() - expected))
            args = BannedFunctionsRule._extract_call_args(source_text, match.end() - 1)
            if args:
                return args[0].strip()

        window = "\n".join(lines[source_line - 1 : source_line + 10])
        matches = list(pattern.finditer(window))
        if not matches:
            return None
        match = min(matches, key=lambda item: abs(item.start() - expected))
        args = BannedFunctionsRule._extract_call_args(window, match.end() - 1)
        if not args:
            return None
        return args[0].strip()

    @classmethod
    def _site_key(
        cls,
        ast_ctx,
        call_fact,
        destination: Optional[str],
    ) -> Optional[Tuple[int, str, str]]:
        normalized = cls._normalize_destination(destination)
        if normalized is None:
            return None
        return (cls._source_line(ast_ctx, call_fact), call_fact.callee, normalized)

    @classmethod
    def _legacy_site_key(cls, issue: Issue) -> Optional[Tuple[int, str, str]]:
        """Recover the legacy rule's (line, callee, destination) identity."""
        callee = next(
            (name for name in cls.TARGET_FUNCS if f"'{name}'" in issue.message),
            None,
        )
        if callee is None:
            return None
        destination_match = re.search(r"\bfor '([^']+)'", issue.message)
        if destination_match is None:
            return None
        destination = cls._normalize_destination(destination_match.group(1))
        if destination is None:
            return None
        return (issue.line_number, callee, destination)

    @staticmethod
    def _is_simple_destination(destination: Optional[str]) -> bool:
        """Return whether shared extent facts describe the exact destination base.

        The size-fact domain currently tracks base object extents, not residual
        capacity after pointer arithmetic or address-of indexed expressions. A
        SAFE proof therefore must not suppress the legacy rule for such shapes.
        """
        if destination is None:
            return False
        normalized = re.sub(r"\s+", "", destination)
        return re.fullmatch(r"[A-Za-z_]\w*(?:->|\.)?\w*", normalized) is not None

    @staticmethod
    def _function_for_call(ast_ctx, call_fact):
        return next(
            (
                fn
                for fn in getattr(ast_ctx, "functions", ())
                if getattr(fn, "name", None) == call_fact.caller
            ),
            None,
        )

    @classmethod
    def _destination_is_parameter(cls, ast_ctx, call_fact, destination: Optional[str]) -> bool:
        """Return whether destination is a formal parameter of the sink wrapper."""
        if destination is None:
            return False
        normalized = re.sub(r"\s+", "", destination)
        if not re.fullmatch(r"[A-Za-z_]\w*", normalized):
            return False
        function = cls._function_for_call(ast_ctx, call_fact)
        if function is None:
            return False
        return any(
            getattr(parameter, "name", None) == normalized
            for parameter in getattr(function, "parameters", ())
        )

    def _residual_capacity_issue(self, file_path: str, ast_ctx, call_fact, destination: Optional[str]) -> Optional[Issue]:
        """Check offset destinations against their local residual capacity.

        Shared size facts intentionally model the base object's extent.  For an
        offset destination such as ``&buf[2]`` that can make the shared result
        look SAFE even though fewer bytes remain from the destination pointer.
        Reuse the legacy capacity resolver before accepting that SAFE proof.
        """
        if destination is None or len(call_fact.sizes) <= 2:
            return None
        size = call_fact.sizes[2]
        if not size.is_exact:
            return None
        function = self._function_for_call(ast_ctx, call_fact)
        if function is None:
            return None
        source_line = self._source_line(ast_ctx, call_fact)
        capacity = self._resolve_dest_capacity(destination, function, source_line, ast_ctx)
        if capacity is None or size.exact_value is None or size.exact_value <= capacity:
            return None
        snippet = _source_snippet(ast_ctx, source_line, f"{call_fact.callee}(...)")
        return self.create_issue(
            file_path=file_path,
            line_number=source_line,
            code_snippet=snippet,
            message=(
                f"Buffer Overflow in '{call_fact.callee}': size argument "
                f"({size.exact_value} bytes) provably exceeds destination buffer "
                f"capacity ({capacity} bytes for '{destination}'). Provable "
                "out-of-bounds write."
            ),
            column_number=max(1, call_fact.column),
            engine="AST",
            fix_type=FixType.SUGGESTED_FIX,
            suggested_fix_replacement=(
                f"Gate the requested size against the {capacity}-byte residual "
                f"capacity before calling {call_fact.callee}()."
            ),
        )

    def _interprocedural_issue(self, file_path: str, ast_ctx, call_fact, safety: SizeSafety) -> Issue:
        size = call_fact.sizes[2]
        capacity = call_fact.extents[0]
        source_line = self._source_line(ast_ctx, call_fact)
        snippet = _source_snippet(ast_ctx, source_line, f"{call_fact.callee}(...)")
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
            line_number=source_line,
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
            if call_fact.callee not in self.TARGET_FUNCS:
                continue
            if len(call_fact.extents) <= 0 or len(call_fact.sizes) <= 2:
                continue

            safety = call_fact.classify(buffer_arg=0, size_arg=2)
            destination = self._destination_for_call(ast_ctx, call_fact)
            site = self._site_key(ast_ctx, call_fact, destination)

            if safety is SizeSafety.SAFE:
                if self._is_simple_destination(destination):
                    if site is not None:
                        handled.add(site)
                    continue

                residual_issue = self._residual_capacity_issue(
                    file_path, ast_ctx, call_fact, destination
                )
                if residual_issue is not None:
                    if site is not None:
                        handled.add(site)
                    issues.append(residual_issue)
                continue

            if safety is SizeSafety.UNSAFE:
                if site is not None:
                    handled.add(site)
                issues.append(
                    self._interprocedural_issue(file_path, ast_ctx, call_fact, safety)
                )
                continue

            if (
                self._informative(call_fact)
                and self._destination_is_parameter(ast_ctx, call_fact, destination)
            ):
                if site is not None:
                    handled.add(site)
                issues.append(
                    self._interprocedural_issue(file_path, ast_ctx, call_fact, safety)
                )

        for issue in legacy:
            site = self._legacy_site_key(issue)
            if site is not None and site in handled:
                continue
            issues.append(issue)

        return sorted(
            issues,
            key=lambda issue: (issue.line_number, issue.column_number, issue.message),
        )
