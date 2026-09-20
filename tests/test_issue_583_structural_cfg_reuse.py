"""Issue #583: reuse structural CFGs across rules (cut residual build_cfg fanout)."""

from unittest.mock import patch

from cgull.analysis_session import analysis_session_for
from cgull.ast_analyzer import CASTParser
from cgull.cfg import construction
from cgull.rules.memory_management.helpers import _ast_cfg_for_function
from cgull.rules.misra_and_style import DeadStoresRule
from cgull.rules.types_and_arrays.division_by_zero import DivisionByZeroRule


def _parse(source: str):
    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    return ctx


def test_cross_rule_consumers_avoid_public_build_cfg_fanout(monkeypatch):
    """Rules/summaries share session structural CFGs instead of public build_cfg."""
    ctx = _parse(
        """
        void free(void *);
        int compute(int x) {
            int y = x + 1;
            if (x) { y = y / x; }
            return y;
        }
        int use(int *p) {
            if (!p) return 0;
            free(p);
            return 1;
        }
        """
    )
    session = analysis_session_for(ctx)
    use_fn = next(f for f in ctx.functions if f.name == "use")
    summaries = session.function_summaries

    original_build = construction.build_cfg
    with patch(
        "cgull.cfg.construction.build_cfg",
        wraps=construction.build_cfg,
    ) as build:
        # Also patch already-bound aliases the way the benchmark harness does.
        import sys

        for module in list(sys.modules.values()):
            name = getattr(module, "__name__", "") or ""
            if not name.startswith("cgull"):
                continue
            if getattr(module, "build_cfg", None) is original_build:
                monkeypatch.setattr(module, "build_cfg", build)

        _ = _ast_cfg_for_function(
            ctx, use_fn, dealloc_funcs={"free", "cfree", "vfree"}, summaries=summaries
        )
        _ = _ast_cfg_for_function(
            ctx, use_fn, dealloc_funcs={"free", "cfree", "vfree"}, summaries=summaries
        )
        DeadStoresRule().scan_ast("t.c", ctx)
        DivisionByZeroRule().scan_ast("t.c", ctx)
        # Session ownership / function summaries already populated above.
        _ = session.ownership_summaries

    assert build.call_count == 0


def test_session_analysis_cfg_reuses_structural_topology():
    ctx = _parse(
        """
        int f(int x) {
            if (x) { return x + 1; }
            return x - 1;
        }
        """
    )
    session = analysis_session_for(ctx)
    structural = session.cfg("f")
    assert structural is not None

    with patch.object(
        construction,
        "clone_cached_structural_cfg",
        side_effect=AssertionError("analysis views must reuse session structural CFGs"),
    ):
        first = session.analysis_cfg("f")
        second = session.analysis_cfg("f", summaries={})

    assert first is not structural
    assert second is not structural
    assert first is not second
    assert set(first.nodes) == set(structural.nodes) == set(second.nodes)


def test_equivalent_annotations_are_reused_and_views_are_isolated():
    from cgull.cfg.model import FunctionSummary

    session = analysis_session_for(_parse(
        "void release(int *); void f(int *p) { release(p); }"
    ))
    with patch.object(construction, "apply_cfg_event_semantics",
                      wraps=construction.apply_cfg_event_semantics) as apply:
        first = session.analysis_cfg("f", summaries={
            "release": FunctionSummary(freed_params={0}),
        })
        freed = next(node for node in first.nodes.values() if "p" in node.freed)
        freed.freed.clear()
        freed.successors.append(999)
        second = session.analysis_cfg("f", summaries={
            "release": FunctionSummary(freed_params={0}),
            "unrelated": FunctionSummary(),
        }, alloc_funcs={"malloc", "extra_allocator"}, dealloc_funcs={"free"})
        assert apply.call_count == 1
        assert second.nodes[freed.node_id].freed == {"p"}
        assert 999 not in second.nodes[freed.node_id].successors
        assert not session.cfg("f").nodes[freed.node_id].freed


def test_annotation_template_tracks_mutable_summaries_effects_and_guards():
    from cgull.cfg.model import FunctionSummary

    session = analysis_session_for(_parse(
        "int valid(int *); void release(int *); "
        "void f(int *p) { if (valid(p)) release(p); }"
    ))
    summaries = {"valid": FunctionSummary(), "release": FunctionSummary()}
    first = session.analysis_cfg("f", summaries=summaries)
    assert not any("p" in add for add, _ in first.edge_facts.values())
    summaries["valid"].truthy_implies_nonnull_params.add(0)
    summaries["release"].freed_params.add(0)
    second = session.analysis_cfg("f", summaries=summaries)
    assert any("p" in add for add, _ in second.edge_facts.values())
    assert any("p" in node.freed for node in second.nodes.values())
    summaries.clear()
    third = session.analysis_cfg("f", summaries=summaries)
    assert not any("p" in add for add, _ in third.edge_facts.values())
    assert not any("p" in node.freed for node in third.nodes.values())
    effects = {"release"}
    fourth = session.analysis_cfg("f", dealloc_funcs=effects)
    assert any("p" in node.freed for node in fourth.nodes.values())
    effects.clear()
    fifth = session.analysis_cfg("f", dealloc_funcs=effects)
    assert not any("p" in node.freed for node in fifth.nodes.values())
    assert len(session._annotated_cfg_cache) == 1


def test_annotation_template_distinguishes_default_and_empty_allocator_sets():
    session = analysis_session_for(_parse(
        "void *malloc(int); void f(void) { void *p = malloc(4); }"
    ))
    default = session.analysis_cfg("f", summaries={})
    disabled = session.analysis_cfg("f", alloc_funcs=set(), summaries={})
    assert any("p" in node.allocated for node in default.nodes.values())
    assert not any("p" in node.allocated for node in disabled.nodes.values())


def test_annotation_template_accounts_for_allocator_name_aliases():
    session = analysis_session_for(_parse(
        "void f(int *custom_alloc) { int *p = custom_alloc; }"
    ))
    first = session.analysis_cfg("f", alloc_funcs=set())
    second = session.analysis_cfg("f", alloc_funcs={"custom_alloc"})
    assert any(node.alias_writes.get("p") == "custom_alloc" for node in first.nodes.values())
    assert not any("p" in node.alias_writes for node in second.nodes.values())
