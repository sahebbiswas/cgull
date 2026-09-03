"""Interprocedural CGULL-002 format-string analysis.

The legacy rule remains the syntactic fallback.  In hybrid/AST scans this
consumer queries the shared translation-unit value-fact engine so literalness
and provenance can flow through helper functions before a format sink is
classified.
"""

from __future__ import annotations

from typing import List, Optional

from .banned_functions import FormatStringRule as _LegacyFormatStringRule
from ..ast_analyzer import CASTContext
from ..cfg.construction import build_cfg, find_function_def
from ..cfg.value_facts import FormatLiteralness, ValueFact, ValueProvenance
from ..cfg.value_interprocedural import _actual_fact
from ..models import AnalysisEngine, Confidence, FixType, Issue
from ..utils import mask_string_and_char_literals


class FormatStringRule(_LegacyFormatStringRule):
    """Detect unsafe format sinks using interprocedural value facts first."""

    implementation_method = "Interprocedural value facts with syntactic fallback"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    analysis_engine = AnalysisEngine.AST

    def _fallback_scan(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        """Run the established syntactic analysis when semantic facts are unavailable."""
        clean_code = getattr(ast_ctx, "clean_source", "") or getattr(ast_ctx, "raw_source", "")
        source_lines = clean_code.splitlines()
        issues: List[Issue] = []
        for line_number, line in enumerate(source_lines, 1):
            if not line.strip():
                continue
            issues.extend(
                super().scan_line(
                    file_path=file_path,
                    line_number=line_number,
                    line_content=line,
                    full_code=clean_code,
                    source_lines=source_lines,
                    masked_line_content=mask_string_and_char_literals(line),
                )
            )
        return issues

    @staticmethod
    def _format_argument_index(call, session) -> Optional[int]:
        callee = getattr(call, "direct_callee", None)
        if callee in FormatStringRule.PRINT_FUNC_ARG_INDEX:
            return FormatStringRule.PRINT_FUNC_ARG_INDEX[callee]

        model = session.semantic_models.for_call(call)
        effect = getattr(model, "effect", None)
        return getattr(effect, "format_argument", None) if effect is not None else None

    @staticmethod
    def _actual_fact(result, event, call, index: int, session) -> ValueFact:
        if index < 0 or index >= len(getattr(call, "actual_arguments", ())):
            return ValueFact(degradations=frozenset({"MISSING_FORMAT_ARGUMENT"}))

        states = getattr(result, "_facts_before", {})
        state = states.get(event.node_id, {})
        return _actual_fact(
            call.actual_arguments[index],
            state,
            session.semantic_models,
            session.value_analysis.summaries,
            128,
        )

    @staticmethod
    def _compact_flow(fact: ValueFact, call, event, fallback_file: str) -> str:
        """Return a compact source-to-sink explanation when evidence is available."""
        source = next(
            (
                evidence
                for evidence in fact.evidence
                if evidence.kind in {"SOURCE", "RETURN"} and evidence.line > 0
            ),
            None,
        )
        sink = getattr(call, "source_location", None) or getattr(event, "source_location", None)
        sink_line = int(getattr(sink, "line_number", 0) or getattr(event, "line_number", 0) or 0)
        if source is None or sink_line <= 0:
            return ""

        source_file = source.file_path or fallback_file
        sink_file = str(getattr(sink, "file_path", "") or fallback_file)
        source_label = f"{source_file}:{source.line}"
        if source.identity:
            source_label += f" ({source.identity})"
        return f" Flow: {source_label} -> {sink_file}:{sink_line}."

    @staticmethod
    def _event_snippet(ast_ctx: CASTContext, line_number: int) -> str:
        lines = getattr(ast_ctx, "source_lines", None) or getattr(ast_ctx, "clean_source", "").splitlines()
        if 0 < line_number <= len(lines):
            return lines[line_number - 1]
        return ""

    def _semantic_issue(self, file_path: str, ast_ctx: CASTContext, event, call, index: int, fact: ValueFact) -> Issue:
        callee = call.direct_callee or call.callee_expression
        arg = call.actual_arguments[index] if index < len(call.actual_arguments) else "<missing>"
        flow = self._compact_flow(fact, call, event, file_path)

        if fact.format_literalness is FormatLiteralness.NON_LITERAL:
            if fact.provenance in {ValueProvenance.UNTRUSTED, ValueProvenance.MIXED}:
                message = (
                    f"Caller-controlled non-literal format string passed to {callee}({arg}). "
                    "An attacker can inject format directives to read or overwrite memory."
                )
            else:
                message = (
                    f"Non-literal format string passed to {callee}({arg}). "
                    "Format string vulnerability allows unintended read/write behavior."
                )
        else:
            message = (
                f"Format string literalness could not be proven for {callee}({arg}); "
                "treating the sink conservatively as potentially unsafe."
            )
        message += flow

        loc = getattr(call, "source_location", None) or getattr(event, "source_location", None)
        line_number = int(getattr(event, "line_number", 0) or 1)
        column_number = int(getattr(loc, "column_number", 0) or 1)
        is_direct_printf = call.direct_callee == "printf"

        issue = self.create_issue(
            file_path=file_path,
            line_number=line_number,
            code_snippet=self._event_snippet(ast_ctx, line_number),
            message=message,
            column_number=column_number,
            engine="Interprocedural",
            fix_type=FixType.SAFE_FIX if is_direct_printf else FixType.SUGGESTED_FIX,
            auto_fix_replacement=f'printf("%s", {arg})' if is_direct_printf else None,
            suggested_fix_replacement=(
                None
                if is_direct_printf
                else f"Use a constant format literal and pass the dynamic value as data (for example, \"%s\", {arg})."
            ),
        )
        if (
            fact.format_literalness is FormatLiteralness.UNKNOWN
            or fact.provenance is ValueProvenance.UNKNOWN
            or fact.degradations
        ):
            issue.confidence = Confidence.LIMITED
        return issue

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        if not getattr(ast_ctx, "has_pycparser", False) or getattr(ast_ctx, "pycparser_ast", None) is None:
            return self._fallback_scan(file_path, ast_ctx)

        session = self.get_analysis_session(ast_ctx)
        value_analysis = session.value_analysis
        issues: List[Issue] = []

        for function in sorted(
            (fn for fn in getattr(ast_ctx, "functions", ()) if getattr(fn, "name", None)),
            key=lambda fn: fn.name,
        ):
            result = value_analysis.function(function.name)
            if result is None:
                continue
            funcdef = find_function_def(ast_ctx.pycparser_ast, function.name)
            if funcdef is None:
                continue
            cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, "line_map", None))
            if not cfg.blocks:
                cfg.build_basic_blocks()

            for event in sorted(cfg.nodes.values(), key=lambda item: item.node_id):
                for call in getattr(event, "calls", ()):
                    index = self._format_argument_index(call, session)
                    if index is None or index >= len(call.actual_arguments):
                        continue
                    arg = call.actual_arguments[index]
                    if self._is_literal_format(arg):
                        continue

                    fact = self._actual_fact(result, event, call, index, session)
                    if fact.format_literalness is FormatLiteralness.LITERAL:
                        continue
                    issues.append(
                        self._semantic_issue(file_path, ast_ctx, event, call, index, fact)
                    )

        return issues
