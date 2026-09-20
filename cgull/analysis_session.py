"""Shared lazy analysis state for one translation unit and configuration profile."""

from __future__ import annotations

from threading import RLock
from time import perf_counter
from typing import Dict
from weakref import WeakSet

from .call_effects import ReturnEffect
from .semantic_models import EMPTY_SEMANTIC_MODELS, SemanticModelRegistry


_SESSION_REGISTRY_LOCK = RLock()
_SESSION_BY_FUNCDEF_ID: Dict[int, "WeakSet[AnalysisSession]"] = {}


def _analysis_session_for_funcdef(funcdef):
    """Return the unique live session owning ``funcdef``, if one exists.

    Multiple sessions may intentionally analyze the same AST with independent
    semantic/configuration state. In that case there is no safe implicit owner
    for the legacy ``build_cfg(funcdef, ...)`` entry point, so callers fall back
    to the neutral structural CFG cache instead of guessing between sessions.
    """
    if funcdef is None:
        return None
    name = getattr(getattr(funcdef, "decl", None), "name", None)
    if not name:
        return None
    with _SESSION_REGISTRY_LOCK:
        owners = _SESSION_BY_FUNCDEF_ID.get(id(funcdef))
        if owners is None:
            return None
        sessions = tuple(
            session for session in owners if session.function_def(name) is funcdef
        )
        if not sessions:
            _SESSION_BY_FUNCDEF_ID.pop(id(funcdef), None)
            return None
    return sessions[0] if len(sessions) == 1 else None


def _discard_serialized_analysis_session():
    """Restore a serialized process-local analysis-session reference as empty."""
    return None


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

    def pointer_range_facts(self, function_name: str):
        """Return cached pointer origin/offset/range facts for one function."""
        return self._session.pointer_range_analysis.function(function_name)

    def pointer_range(self, function_name: str, location: str, line=None):
        """Query one pointer range fact at a source event/use line."""
        return self._session.pointer_range_analysis.query(function_name, location, line)

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
        from .cfg.construction import build_function_def_index

        self._function_defs = build_function_def_index(
            getattr(ast_context, "pycparser_ast", None)
        )
        self._cfg_lock = RLock()
        self._cfg_cache: Dict[str, object] = {}
        self._event_facts_cache = None
        self._cfg_construction_count = 0
        self._cfg_construction_seconds = 0.0
        self._call_graph = None
        self._function_summary_results = {}
        self._ownership_summary_result = None
        self._ownership_effects_cache: Dict[str, object] = {}
        self._value_analysis_result = None
        self._size_analysis_result = None
        self._pointer_range_analysis_result = None
        self._summary_construction_count = 0
        self._queries = AnalysisQueries(self)
        self._register_cfg_owners()

    def __reduce__(self):
        """Do not carry process-local caches and synchronization state across workers."""
        return (_discard_serialized_analysis_session, ())

    def _register_cfg_owners(self) -> None:
        with _SESSION_REGISTRY_LOCK:
            for funcdef in self._function_defs.values():
                owners = _SESSION_BY_FUNCDEF_ID.get(id(funcdef))
                if owners is None:
                    owners = WeakSet()
                    _SESSION_BY_FUNCDEF_ID[id(funcdef)] = owners
                owners.add(self)

    @property
    def function_defs(self):
        """One-pass function-definition index for this translation unit."""
        return self._function_defs

    def function_def(self, function_name: str):
        """Return a pycparser ``FuncDef`` in O(1) after session construction."""
        return self._function_defs.get(function_name)

    def _raw_cfg(self, function_name: str):
        """Return the session-owned structural CFG without forcing call-graph recursion."""
        with self._cfg_lock:
            if function_name not in self._cfg_cache:
                funcdef = self.function_def(function_name)
                if funcdef is None:
                    return None
                from .cfg.construction import clone_cached_structural_cfg

                started = perf_counter()
                cfg = clone_cached_structural_cfg(
                    funcdef,
                    line_map=getattr(self.ast_context, "line_map", None),
                )
                self._cfg_construction_seconds += perf_counter() - started
                self._cfg_construction_count += 1
                self._cfg_cache[function_name] = cfg
            return self._cfg_cache[function_name]

    @property
    def call_graph(self):
        with self._cfg_lock:
            if self._call_graph is None:
                from .cfg.call_graph import build_translation_unit_call_graph

                self._call_graph = build_translation_unit_call_graph(
                    self.ast_context,
                    function_defs=self.function_defs,
                    cfg_provider=self._raw_cfg,
                )
            return self._call_graph

    def cfg(self, function_name: str):
        """Return the canonical resolved structural CFG for ``function_name``.

        Callers must treat this graph as read-only. Analyses that attach or mutate
        data-flow state should use :meth:`analysis_cfg` instead.
        """
        function = self.call_graph.function(function_name)
        return function.cfg if function is not None else None

    def analysis_cfg(
        self,
        function_name: str,
        *,
        alloc_funcs=None,
        dealloc_funcs=None,
        realloc_funcs=None,
        summaries=None,
    ):
        """Return an isolated CFG view sharing the session's structural topology."""
        cfg = self.cfg(function_name)
        if cfg is None:
            return None
        from .cfg.construction import apply_cfg_event_semantics, clone_structural_cfg

        clone = clone_structural_cfg(cfg)
        if any(
            value is not None
            for value in (alloc_funcs, dealloc_funcs, realloc_funcs, summaries)
        ):
            with self._cfg_lock:
                event_cache = self._event_cache()
                apply_cfg_event_semantics(
                    clone,
                    event_cache=event_cache,
                    alloc_funcs=alloc_funcs,
                    dealloc_funcs=dealloc_funcs,
                    realloc_funcs=realloc_funcs,
                    summaries=summaries,
                    line_map=event_cache.line_map,
                )
        return clone

    def _event_cache(self):
        from .cfg.event_cache import EventFactsCache

        with self._cfg_lock:
            line_map = getattr(self.ast_context, "line_map", None)
            if self._event_facts_cache is None or self._event_facts_cache.line_map is not line_map:
                self._event_facts_cache = EventFactsCache(line_map)
            return self._event_facts_cache

    def _analysis_cfg_for_funcdef(
        self,
        funcdef,
        *,
        alloc_funcs=None,
        dealloc_funcs=None,
        realloc_funcs=None,
        summaries=None,
    ):
        name = getattr(getattr(funcdef, "decl", None), "name", None)
        if not name or self.function_def(name) is not funcdef:
            return None
        return self.analysis_cfg(
            name,
            alloc_funcs=alloc_funcs,
            dealloc_funcs=dealloc_funcs,
            realloc_funcs=realloc_funcs,
            summaries=summaries,
        )

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

    def function_summary_result(
        self, alloc_funcs=None, dealloc_funcs=None, realloc_funcs=None, *,
        call_effects=None, fixed_point_config=None,
    ):
        """Return an isolated result for the requested effective summary inputs.

        Omitted inputs retain the standalone engine's built-in semantics. The
        default property separately supplies this session's declarative models.
        AST/profile identity is implicit in session ownership; imported facts
        and mutable registry contents are snapshotted into each lookup key.
        """
        from .cfg.summaries import (
            analyze_function_summaries_detailed, copy_function_summary_result,
            function_summary_input_key,
        )

        with self._cfg_lock:
            key = function_summary_input_key(
                self.ast_context, alloc_funcs, dealloc_funcs, realloc_funcs,
                call_effects=call_effects, fixed_point_config=fixed_point_config,
            )
            if key not in self._function_summary_results:
                result = analyze_function_summaries_detailed(
                    self.ast_context,
                    alloc_funcs=alloc_funcs,
                    dealloc_funcs=dealloc_funcs,
                    realloc_funcs=realloc_funcs,
                    call_graph=self.call_graph,
                    call_effects=call_effects,
                    fixed_point_config=fixed_point_config,
                    event_cache=self._event_cache(),
                )
                self._function_summary_results[key] = copy_function_summary_result(result)
                self._summary_construction_count += 1
            # FunctionSummary contains mutable sets, so a shallow mapping copy
            # would allow a rule to corrupt subsequent consumers' facts.
            return copy_function_summary_result(self._function_summary_results[key])

    def _ensure_function_summaries(self):
        alloc_funcs, dealloc_funcs, realloc_funcs = self._memory_effect_sets()
        return self.function_summary_result(
            alloc_funcs, dealloc_funcs, realloc_funcs,
            call_effects=self.semantic_models.call_effects,
        )

    def _ensure_ownership_summaries(self):
        if self._ownership_summary_result is None:
            from .cfg.ownership import analyze_ownership_summaries_detailed

            self._ownership_summary_result = analyze_ownership_summaries_detailed(
                self.ast_context,
                call_graph=self.call_graph,
                call_effects=self.semantic_models.call_effects,
                event_cache=self._event_cache(),
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

    def _ensure_pointer_range_analysis(self):
        if self._pointer_range_analysis_result is None:
            from .cfg.pointer_ranges import analyze_translation_unit_pointer_ranges

            self._pointer_range_analysis_result = analyze_translation_unit_pointer_ranges(
                self.ast_context,
                size_analysis=self.size_analysis,
                value_analysis=self.value_analysis,
                semantic_models=self.semantic_models,
                call_graph=self.call_graph,
            )
        return self._pointer_range_analysis_result

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
    def pointer_range_analysis(self):
        """Lazily computed pointer origin/offset/accessibility facts."""
        return self._ensure_pointer_range_analysis()

    @property
    def summary_construction_count(self) -> int:
        return self._summary_construction_count

    @property
    def cfg_construction_count(self) -> int:
        """Number of canonical per-function CFGs materialized by this session."""
        return self._cfg_construction_count

    @property
    def cfg_construction_seconds(self) -> float:
        """Wall time spent materializing canonical session CFG views."""
        return self._cfg_construction_seconds

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