"""Interprocedural CGULL-030 command-injection analysis."""

from __future__ import annotations

from typing import List, Optional, Set, Tuple

from .banned_functions import CommandInjectionRule as _LegacyCommandInjectionRule
from ..ast_analyzer import CASTContext
from ..cfg.construction import build_cfg, find_function_def
from ..cfg.value_facts import ValueFact, ValueProvenance
from ..cfg.value_interprocedural import _actual_fact as _resolve_actual_fact
from ..models import AnalysisEngine, Confidence, FixType, Issue
from ..semantic_models import SemanticLocationKind, ValidationProperty
from ..utils import mask_string_and_char_literals


class CommandInjectionRule(_LegacyCommandInjectionRule):
    """Classify command sinks using propagated provenance when available."""

    implementation_method = "Interprocedural value provenance with syntactic fallback"
    implementation_complexity = "Medium"
    analysis_engine = AnalysisEngine.AST

    def _fallback_scan(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
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
    def _sink_argument_indexes(call, session) -> Tuple[int, ...]:
        if call.direct_callee in CommandInjectionRule.TARGET_FUNCS:
            return (0,)
        sink = session.semantic_models.sink_for(call)
        if sink is None:
            return ()
        indexes = []
        for requirement in sink.requirements:
            if (
                requirement.location.kind is SemanticLocationKind.ARGUMENT
                and ValidationProperty.ALLOWLISTED in requirement.properties
                and requirement.location.argument_index is not None
            ):
                indexes.append(requirement.location.argument_index)
        return tuple(sorted(set(indexes)))

    @staticmethod
    def _fact_for_actual(result, event, call, index: int, session) -> ValueFact:
        if index < 0 or index >= len(getattr(call, "actual_arguments", ())):
            return ValueFact(degradations=frozenset({"MISSING_COMMAND_ARGUMENT"}))
        state = getattr(result, "_facts_before", {}).get(event.node_id, {})
        return _resolve_actual_fact(
            call.actual_arguments[index], state, session.semantic_models,
            session.value_analysis.summaries, 128,
        )

    @staticmethod
    def _simple_identifier(text: str) -> Optional[str]:
        value = text.strip()
        return value if value.isidentifier() else None

    @classmethod
    def _sanitized_locations_before(cls, cfg, sink_node_id: int, session) -> Set[str]:
        """Collect only still-valid explicit in-place sanitizer effects."""
        sanitized: Set[str] = set()
        for event in sorted(cfg.nodes.values(), key=lambda item: item.node_id):
            if event.node_id >= sink_node_id:
                break

            # Any subsequent write replaces the sanitized value.
            sanitized.difference_update(getattr(event, "written_vars", ()) or ())

            for call in getattr(event, "calls", ()):
                effect = session.semantic_models.effect_for(call)
                sanitizer_indexes = set(effect.sanitizes) if effect is not None else set()

                # An unmodeled call receiving a sanitized object may mutate it;
                # do not retain a proof across that call.
                if effect is None:
                    for actual in call.actual_arguments:
                        name = cls._simple_identifier(actual)
                        if name:
                            sanitized.discard(name)

                for index in sanitizer_indexes:
                    if index >= len(call.actual_arguments):
                        continue
                    name = cls._simple_identifier(call.actual_arguments[index])
                    if name:
                        sanitized.add(name)
        return sanitized

    @staticmethod
    def _compact_flow(fact: ValueFact, call, event, fallback_file: str) -> str:
        source = next(
            (e for e in fact.evidence if e.kind in {"SOURCE", "RETURN"} and e.line > 0),
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
    def _snippet(ast_ctx: CASTContext, line_number: int) -> str:
        lines = getattr(ast_ctx, "source_lines", None) or getattr(ast_ctx, "clean_source", "").splitlines()
        return lines[line_number - 1] if 0 < line_number <= len(lines) else ""

    def _issue(self, file_path: str, ast_ctx: CASTContext, event, call, index: int, fact: ValueFact) -> Issue:
        callee = call.direct_callee or call.callee_expression
        arg = call.actual_arguments[index] if index < len(call.actual_arguments) else "<missing>"
        flow = self._compact_flow(fact, call, event, file_path)
        if fact.provenance in {ValueProvenance.UNTRUSTED, ValueProvenance.MIXED}:
            message = (
                f"Untrusted command data reaches {callee}({arg}); an attacker may inject "
                f"OS command content.{flow}"
            )
        else:
            message = (
                f"Command provenance could not be proven safe for {callee}({arg}); "
                f"treating the execution sink conservatively.{flow}"
            )
        loc = getattr(call, "source_location", None) or getattr(event, "source_location", None)
        line_number = int(getattr(event, "line_number", 0) or 1)
        issue = self.create_issue(
            file_path=file_path,
            line_number=line_number,
            code_snippet=self._snippet(ast_ctx, line_number),
            message=message,
            column_number=int(getattr(loc, "column_number", 0) or 1),
            engine="Interprocedural",
            fix_type=FixType.SUGGESTED_FIX,
            suggested_fix_replacement=(
                "Avoid shell execution; prefer execve() with a fixed executable/argv, "
                "or apply a complete allowlist sanitizer modeled in semantic_models."
            ),
        )
        if fact.provenance is ValueProvenance.UNKNOWN or fact.degradations:
            issue.confidence = Confidence.LIMITED
        return issue

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        if not getattr(ast_ctx, "has_pycparser", False) or getattr(ast_ctx, "pycparser_ast", None) is None:
            return self._fallback_scan(file_path, ast_ctx)

        session = self.get_analysis_session(ast_ctx)
        issues: List[Issue] = []
        for function in sorted(
            (fn for fn in getattr(ast_ctx, "functions", ()) if getattr(fn, "name", None)),
            key=lambda fn: fn.name,
        ):
            result = session.value_analysis.function(function.name)
            if result is None:
                continue
            funcdef = find_function_def(ast_ctx.pycparser_ast, function.name)
            if funcdef is None:
                continue
            cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, "line_map", None))
            if not cfg.blocks:
                cfg.build_basic_blocks()

            for event in sorted(cfg.nodes.values(), key=lambda item: item.node_id):
                sanitized = self._sanitized_locations_before(cfg, event.node_id, session)
                for call in getattr(event, "calls", ()):
                    for index in self._sink_argument_indexes(call, session):
                        if index >= len(call.actual_arguments):
                            continue
                        arg = call.actual_arguments[index]
                        if self._is_literal_arg(arg):
                            continue
                        if self._simple_identifier(arg) in sanitized:
                            continue
                        fact = self._fact_for_actual(result, event, call, index, session)
                        if fact.provenance is ValueProvenance.TRUSTED:
                            continue
                        issues.append(self._issue(file_path, ast_ctx, event, call, index, fact))
        return issues
