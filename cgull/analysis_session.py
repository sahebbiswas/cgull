"""Shared lazy analysis state for one translation unit and configuration profile."""

from __future__ import annotations

from typing import Dict

from .call_effects import ReturnEffect
from .semantic_models import EMPTY_SEMANTIC_MODELS, SemanticModelRegistry


class AnalysisQueries:
    """Lazy, cached high-level query interface bound to one analysis session."""

    def __init__(self, session: "AnalysisSession") -> None:
        self._session = session
        self._cache: Dict[str, object] = {}

    def unvalidated_sink_flows(self):
        key = "unvalidated_sink_flows"
        if key not in self._cache:
            from .cfg.security_queries import query_unvalidated_sink_flows

            self._cache[key] = query_unvalidated_sink_flows(
                self._session.ast_context,
                self._session.semantic_models,
            )
        return self._cache[key]

    def value_facts(self, function_name: str):
        """Return cached interprocedural value facts for one function."""
        return self._session.value_analysis.function(function_name)

    def size_facts(self):
        """Return cached bounded interprocedural size/extent facts for the TU."""
        return self._session.size_analysis

    def ownership_summaries(self):
        """Return cached allocation ownership/effect summaries for the TU."""
        return self._session.ownership_summaries


class AnalysisSession:
    """Shared analysis state for exactly one TU/configuration-profile scan."""

    def __init__(
        self,
        ast_context: object,
        *,
        semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS,
    ) -> None:
        self.ast_context = ast_context
        self.semantic_models = (
            semantic_models
            if isinstance(semantic_models, SemanticModelRegistry)
            else EMPTY_SEMANTIC_MODELS
        )
        self._call_graph = None
        self._function_summary_result = None
        self._ownership_summary_result = None
        self._ownership_effects_cache: Dict[str, object] = {}
        self._value_analysis_result = None
        self._size_analysis_result = None
        self._summary_construction_count = 0
        self._queries = AnalysisQueries(self)

    @property
    def call_graph(self):
        if self._call_graph is None:
            from .cfg.call_graph import build_translation_unit_call_graph

            self._call_graph = build_translation_unit_call_graph(self.ast_context)
        return self._call_graph

    def _memory_effect_sets(self):
        """Translate declarative effects into the legacy CFG summary inputs."""
        alloc = set()
        dealloc = set()
        realloc = set()
        for function, effect in self.semantic_models.call_effects.effects.items():
            if effect.return_effect is ReturnEffect.ALLOCATION:
                alloc.add(function)
            if effect.deallocates:
                dealloc.add(function)
            if effect.return_effect is ReturnEffect.ALLOCATION and effect.deallocates:
                realloc.add(function)
        return alloc, dealloc, realloc

    def _ensure_function_summaries(self):
        if self._function_summary_result is None:
            from .cfg.summaries import analyze_function_summaries_detailed

            alloc_funcs, dealloc_funcs, realloc_funcs = self._memory_effect_sets()
            self._summary_construction_count += 1
            self._function_summary_result = analyze_function_summaries_detailed(
                self.ast_context,
                alloc_funcs=alloc_funcs,
                dealloc_funcs=dealloc_funcs,
                realloc_funcs=realloc_funcs,
                call_graph=self.call_graph,
                call_effects=self.semantic_models.call_effects,
            )
        return self._function_summary_result

    def _ensure_ownership_summaries(self):
        if self._ownership_summary_result is None:
            from .cfg.ownership import analyze_ownership_summaries_detailed

            self._ownership_summary_result = analyze_ownership_summaries_detailed(
                self.ast_context,
                call_graph=self.call_graph,
                call_effects=self.semantic_models.call_effects,
            )
        return self._ownership_summary_result

    def ownership_effects(self, function_name: str, cfg):
        """Return cached per-node ownership effects for one function CFG."""
        if function_name not in self._ownership_effects_cache:
            from .cfg.ownership import ownership_effects_for_cfg

            self._ownership_effects_cache[function_name] = ownership_effects_for_cfg(
                cfg,
                self.ownership_summaries,
                call_effects=self.semantic_models.call_effects,
            )
        return self._ownership_effects_cache[function_name]

    def _ensure_value_analysis(self):
        if self._value_analysis_result is None:
            from .cfg.value_interprocedural import analyze_translation_unit_value_dataflow

            self._value_analysis_result = analyze_translation_unit_value_dataflow(
                self.ast_context,
                self.semantic_models,
                call_graph=self.call_graph,
            )
        return self._value_analysis_result

    def _ensure_size_analysis(self):
        if self._size_analysis_result is None:
            from .cfg.size_facts import analyze_translation_unit_size_dataflow

            self._size_analysis_result = analyze_translation_unit_size_dataflow(
                self.ast_context,
                call_graph=self.call_graph,
            )
        return self._size_analysis_result

    @property
    def function_summaries(self):
        return self._ensure_function_summaries().summaries

    @property
    def summary_diagnostics(self):
        return self._ensure_function_summaries().diagnostics

    @property
    def summary_iterations_by_scc(self):
        return self._ensure_function_summaries().iterations_by_scc

    @property
    def ownership_summaries(self):
        return self._ensure_ownership_summaries().summaries

    @property
    def ownership_diagnostics(self):
        return self._ensure_ownership_summaries().diagnostics

    @property
    def ownership_iterations_by_scc(self):
        return self._ensure_ownership_summaries().iterations_by_scc

    @property
    def value_analysis(self):
        """Lazily computed provenance/format analysis shared by all rules."""
        return self._ensure_value_analysis()

    @property
    def size_analysis(self):
        """Lazily computed bounded size/extent analysis shared by all rules."""
        return self._ensure_size_analysis()

    @property
    def summary_construction_count(self) -> int:
        return self._summary_construction_count

    @property
    def queries(self) -> AnalysisQueries:
        return self._queries


def analysis_session_for(
    ast_context: object,
    *,
    semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS,
) -> AnalysisSession:
    """Return the context's shared session, rejecting incompatible model registries."""
    existing = getattr(ast_context, "analysis_session", None)
    if isinstance(existing, AnalysisSession):
        requested = (
            semantic_models
            if isinstance(semantic_models, SemanticModelRegistry)
            else EMPTY_SEMANTIC_MODELS
        )
        if existing.semantic_models is EMPTY_SEMANTIC_MODELS and requested is not EMPTY_SEMANTIC_MODELS:
            existing.semantic_models = requested
        elif (
            requested is not EMPTY_SEMANTIC_MODELS
            and existing.semantic_models is not EMPTY_SEMANTIC_MODELS
            and requested != existing.semantic_models
        ):
            raise ValueError(
                "AST rules sharing one analysis session must use the same semantic model registry"
            )
        return existing

    session = AnalysisSession(ast_context, semantic_models=semantic_models)
    setattr(ast_context, "analysis_session", session)
    return session
