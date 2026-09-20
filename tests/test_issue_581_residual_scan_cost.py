"""Issue #581: residual CFG fanout / project-summary construction mitigations."""

from unittest.mock import patch

from cgull.analysis_session import analysis_session_for
from cgull.ast_analyzer import CASTParser
from cgull.cfg import construction
from cgull.project_analysis import ProjectSummaryIndex
from cgull.semantic_models import EMPTY_SEMANTIC_MODELS


def _parse(source: str):
    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    return ctx


def test_clone_structural_cfg_copies_block_topology_without_rebuild():
    ctx = _parse(
        """
        int f(int x) {
            if (x) { x = x + 1; }
            else { x = x - 1; }
            return x;
        }
        """
    )
    session = analysis_session_for(ctx)
    structural = session.cfg("f")
    assert structural is not None
    assert structural.blocks

    with patch.object(
        type(structural),
        "build_basic_blocks",
        side_effect=AssertionError("clone must reuse block topology"),
    ):
        cloned = construction.clone_structural_cfg(structural)

    assert cloned is not structural
    assert {
        block_id: (
            tuple(node.node_id for node in block.nodes),
            tuple(block.predecessors),
            tuple(block.successors),
        )
        for block_id, block in sorted(cloned.blocks.items())
    } == {
        block_id: (
            tuple(node.node_id for node in block.nodes),
            tuple(block.predecessors),
            tuple(block.successors),
        )
        for block_id, block in sorted(structural.blocks.items())
    }
    cloned.nodes[structural.entry].reads.add("__mutated__")
    assert "__mutated__" not in structural.nodes[structural.entry].reads


def test_project_summary_index_reuses_session_across_domains():
    caller = _parse(
        """
        void release(int *p);
        int caller(int *p) {
            release(p);
            return *p;
        }
        """
    )
    callee = _parse(
        """
        void free(void *);
        void release(int *p) { free(p); }
        """
    )
    index = ProjectSummaryIndex(
        {"caller.c": caller, "callee.c": callee},
        EMPTY_SEMANTIC_MODELS,
        required_domains=("function", "ownership"),
    )
    before = dict(index.sessions)
    index.build()
    assert index.sessions["caller.c"] is before["caller.c"]
    assert index.sessions["callee.c"] is before["callee.c"]
    assert caller.analysis_session is before["caller.c"]
    assert callee.analysis_session is before["callee.c"]
    assert "release" in index.outputs["callee.c"]["function"]
    assert "release" in index.outputs["callee.c"]["ownership"]


def test_project_summary_import_change_invalidates_summary_caches_only():
    leaf = _parse(
        """
        void free(void *);
        void release(int *p) { free(p); }
        """
    )
    index = ProjectSummaryIndex(
        {"leaf.c": leaf},
        EMPTY_SEMANTIC_MODELS,
        required_domains=("function",),
    )
    session = index.sessions["leaf.c"]
    session.function_summaries  # populate
    assert session._function_summary_results
    graph = session.call_graph
    index._invalidate_session_summary_caches(session)
    assert session._function_summary_results == {}
    assert session.call_graph is graph
    # Re-evaluate still uses the same session object.
    index._evaluate("leaf.c", {"function": {}})
    assert index.sessions["leaf.c"] is session
    assert session.call_graph is graph


def test_memory_rule_ast_cfg_shared_across_equivalent_requests():
    from unittest.mock import patch

    from cgull.analysis_session import AnalysisSession
    from cgull.rules.memory_management.helpers import _ast_cfg_for_function

    ctx = _parse(
        """
        void free(void *);
        void release(int *p) { free(p); }
        int use(int *p) {
            release(p);
            return *p;
        }
        """
    )
    fn = next(f for f in ctx.functions if f.name == "use")
    session = analysis_session_for(ctx)
    summaries = session.function_summaries

    calls = {"n": 0}
    original = AnalysisSession.analysis_cfg

    def counting(self, function_name, **kwargs):
        calls["n"] += 1
        return original(self, function_name, **kwargs)

    with patch.object(AnalysisSession, "analysis_cfg", counting):
        first = _ast_cfg_for_function(
            ctx, fn, dealloc_funcs={"free", "cfree", "vfree"}, summaries=summaries
        )
        second = _ast_cfg_for_function(
            ctx, fn, dealloc_funcs={"free", "cfree", "vfree"}, summaries=summaries
        )
        third = _ast_cfg_for_function(
            ctx, fn, dealloc_funcs={"free"}, summaries=summaries
        )

    assert first is second
    assert first is not third
    # Annotated template cache avoids a second analysis_cfg for equivalent inputs.
    assert calls["n"] == 2
