"""Shared lazy analysis state for one translation unit and configuration profile."""

from __future__ import annotations

from typing import Dict

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


class AnalysisSession:
    """Shared analysis state for exactly one TU/configuration-profile scan.

    Expensive domains are created only when requested. The session is attached to
    the existing ``CASTContext`` so AST rules can share it without changing the
    long-standing ``scan_ast(file_path, ast_ctx)`` extension signature.

    Configuration-profile isolation is provided by the scan pipeline: each profile
    is parsed into a distinct ``CASTContext``, and therefore owns a distinct session.
    """

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
        self._function_summaries = None
        self._summary_construction_count = 0
        self._queries = AnalysisQueries(self)

    @property
    def call_graph(self):
        if self._call_graph is None:
            from .cfg.call_graph import build_translation_unit_call_graph

            self._call_graph = build_translation_unit_call_graph(self.ast_context)
        return self._call_graph

    @property
    def function_summaries(self):
        if self._function_summaries is None:
            from .cfg.summaries import analyze_function_summaries

            self._summary_construction_count += 1
            self._function_summaries = analyze_function_summaries(self.ast_context)
        return self._function_summaries

    @property
    def summary_construction_count(self) -> int:
        """Number of actual function-summary constructions performed by this session."""
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
