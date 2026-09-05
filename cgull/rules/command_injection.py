"""Interprocedural CGULL-030 command-injection analysis."""

from __future__ import annotations

from typing import Dict, FrozenSet, List, Optional, Set, Tuple

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
    def _sanitized_state_before(cls, cfg, session) -> Dict[int, FrozenSet[str]]:
        """Compute must-sanitized locations at each event in one CFG dataflow pass.

        Sanitization is a proof that must hold on every path reaching a sink, so
        predecessor states merge by intersection.  Walking basic blocks follows
        the CFG's execution order rather than creation-time ``node_id`` order,
        which is intentionally reversed for portions of CFG construction.
        """
        if not cfg.blocks:
            cfg.build_basic_blocks()
        if not cfg.blocks:
            return {}

        entry = cfg.node_to_block.get(cfg.entry) if cfg.entry else min(cfg.blocks)
        if entry not in cfg.blocks:
            entry = min(cfg.blocks)

        reachable: Set[int] = set()
        queue = [entry]
        while queue:
            block_id = queue.pop(0)
            if block_id in reachable or block_id not in cfg.blocks:
                continue
            reachable.add(block_id)
            queue.extend(cfg.blocks[block_id].successors)

        incoming: Dict[int, Optional[Set[str]]] = {
            block_id: None for block_id in reachable
        }
        incoming[entry] = set()
        before: Dict[int, FrozenSet[str]] = {}
        work = [entry]

        while work:
            block_id = work.pop(0)
            block_in = incoming.get(block_id)
            if block_in is None:
                continue
            state = set(block_in)
            block = cfg.blocks[block_id]

            for event in block.nodes:
                before[event.node_id] = frozenset(state)

                # A write replaces the value for which sanitization was proven.
                state.difference_update(getattr(event, "writes", ()) or ())

                for call in getattr(event, "calls", ()):
                    effect = session.semantic_models.effect_for(call)

                    # An unknown call may mutate referenced command storage.  A
                    # modeled sanitizer below can establish a fresh proof for
                    # its declared argument positions in the same event.
                    if effect is None:
                        for actual in call.actual_arguments:
                            name = cls._simple_identifier(actual)
                            if name:
                                state.discard(name)
                        continue

                    for index in effect.sanitizes:
                        if index >= len(call.actual_arguments):
                            continue
                        name = cls._simple_identifier(call.actual_arguments[index])
                        if name:
                            state.add(name)

            for successor in block.successors:
                if successor not in reachable:
                    continue
                old = incoming.get(successor)
                merged = set(state) if old is None else old & state
                if old is None or merged != old:
                    incoming[successor] = merged
                    if successor not in work:
                        work.append(successor)

        return before

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
            sanitized_before = self._sanitized_state_before(cfg, session)

            # Finding order remains deterministic/source-oriented even though
            # sanitizer facts themselves come from CFG control-flow order.
            events = sorted(
                cfg.nodes.values(),
                key=lambda item: (item.line_number, item.node_id),
            )
            for event in events:
                sanitized = sanitized_before.get(event.node_id, frozenset())
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
