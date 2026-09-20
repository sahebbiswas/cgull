"""Semantic-key and isolation regressions for the whole-TU summary cache."""
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cgull.analysis_session import AnalysisSession, analysis_session_for
from cgull.ast_analyzer import CASTParser
from cgull.call_effects import BUILTIN_CALL_EFFECTS, CallEffectModel, CallEffectRegistry, ReturnEffect
from cgull.cfg.fixed_point import FixedPointConfig
from cgull.cfg.model import FunctionSummary
from cgull.cfg.ownership import analyze_ownership_summaries_detailed
from cgull.cfg.summaries import analyze_function_summaries, analyze_function_summaries_detailed


def context():
    ctx = CASTParser().parse('''
        void *custom(void);
        void release(void *p);
        void *make(void) { return custom(); }
        void drop(void *p) { release(p); }
    ''')
    assert ctx.has_pycparser
    return ctx


def test_equivalent_registry_content_and_set_order_share_engine_run():
    ctx = context()
    session = analysis_session_for(ctx)
    first = CallEffectRegistry(dict(BUILTIN_CALL_EFFECTS.effects))
    second = CallEffectRegistry(dict(reversed(list(first.effects.items()))))
    with patch('cgull.cfg.summaries.analyze_function_summaries_detailed',
               wraps=analyze_function_summaries_detailed) as engine:
        left = session.function_summary_result({'malloc', 'custom'}, call_effects=first)
        right = session.function_summary_result({'custom', 'malloc'}, call_effects=second,
                                                fixed_point_config=FixedPointConfig())
    assert left == right
    assert left.summaries['make'].returns_allocation
    assert engine.call_count == session.summary_construction_count == 1


def test_legacy_and_ownership_consumers_reuse_same_requested_registry():
    ctx = context()
    registry = BUILTIN_CALL_EFFECTS.merged({
        'custom': CallEffectModel('custom', return_effect=ReturnEffect.ALLOCATION),
    })
    with patch('cgull.cfg.summaries.analyze_function_summaries_detailed',
               wraps=analyze_function_summaries_detailed) as engine:
        analyze_function_summaries(ctx, call_effects=registry)
        owned = analyze_ownership_summaries_detailed(ctx, call_effects=registry)
        plain = analyze_ownership_summaries_detailed(ctx)
    assert owned.summaries['make'].returns_allocation
    assert not plain.summaries['make'].returns_allocation
    assert engine.call_count == 2


def test_effects_imports_and_fixed_point_options_invalidate_by_content():
    ctx = context()
    session = analysis_session_for(ctx)
    original = session.function_summary_result()
    assert not original.summaries['make'].returns_allocation
    allocated = session.function_summary_result(alloc_funcs={'custom'})
    assert allocated.summaries['make'].returns_allocation
    freed = session.function_summary_result(dealloc_funcs={'release'})
    assert freed.summaries['drop'].freed_params == {0}
    session.function_summary_result(realloc_funcs={'custom'})
    registry = CallEffectRegistry(dict(BUILTIN_CALL_EFFECTS.effects))
    session.function_summary_result(call_effects=registry)
    registry.effects['custom'] = CallEffectModel('custom', return_effect=ReturnEffect.ALLOCATION)
    assert session.function_summary_result(call_effects=registry).summaries['make'].returns_allocation
    ctx.project_summaries = {'function': {'custom': FunctionSummary(returns_allocation=True)}}
    assert session.function_summary_result().summaries['make'].returns_allocation
    ctx.project_summaries['function']['custom'].returns_allocation = False
    assert not session.function_summary_result().summaries['make'].returns_allocation
    session.function_summary_result(fixed_point_config=FixedPointConfig(max_iterations_per_scc=1))
    assert session.summary_construction_count == 8


def test_results_do_not_share_mutable_mappings_or_summary_sets():
    session = analysis_session_for(context())
    first = session.function_summary_result(dealloc_funcs={'release'})
    first.summaries['drop'].freed_params.clear()
    first.summaries['make'].returns_allocation = True
    first.summaries.pop('malloc')
    first.iterations_by_scc.clear()
    second = session.function_summary_result(dealloc_funcs={'release'})
    assert second.summaries['drop'].freed_params == {0}
    assert not second.summaries['make'].returns_allocation
    assert 'malloc' in second.summaries
    assert second.iterations_by_scc
    assert session.summary_construction_count == 1


def test_concurrent_requests_compute_once_and_sessions_remain_independent():
    ctx = context()
    session = analysis_session_for(ctx)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: session.function_summary_result(), range(8)))
    assert all(result == results[0] for result in results)
    assert session.summary_construction_count == 1
    other = AnalysisSession(ctx)
    other.function_summary_result()
    assert other.summary_construction_count == 1


def test_default_property_reuses_canonical_explicit_key():
    session = analysis_session_for(context())
    default = session.function_summaries
    explicit = session.function_summary_result(
        *session._memory_effect_sets(), call_effects=session.semantic_models.call_effects,
    )
    assert default == explicit.summaries
    assert session.summary_construction_count == 1


def test_none_empty_and_custom_memory_sets_match_uncached_engine():
    ctx = context()
    session = analysis_session_for(ctx)
    for options in ({}, {'alloc_funcs': set()}, {'dealloc_funcs': set()},
                    {'realloc_funcs': set()}, {'alloc_funcs': {'custom'}},
                    {'dealloc_funcs': {'release'}}, {'realloc_funcs': {'custom'}}):
        assert session.function_summary_result(**options) == analyze_function_summaries_detailed(ctx, **options)
    # None and empty sets must never be collapsed when their semantics differ.
    assert session.summary_construction_count == 7


def test_default_property_tracks_late_session_model_installation():
    from cgull.semantic_models import SemanticModelRegistry

    ctx = context()
    session = analysis_session_for(ctx)
    assert not session.function_summaries['make'].returns_allocation
    registry = SemanticModelRegistry(call_effects=BUILTIN_CALL_EFFECTS.merged({
        'custom': CallEffectModel('custom', return_effect=ReturnEffect.ALLOCATION),
    }))
    assert analysis_session_for(ctx, semantic_models=registry) is session
    assert session.function_summaries['make'].returns_allocation
    assert session.summary_construction_count == 2
