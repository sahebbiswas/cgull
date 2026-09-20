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


def test_cross_rule_consumers_avoid_public_build_cfg_fanout():
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
            if getattr(module, "build_cfg", None) is construction.build_cfg:
                setattr(module, "build_cfg", build)

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
