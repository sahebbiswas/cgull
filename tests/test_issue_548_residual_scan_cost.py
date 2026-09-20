"""Issue #548: residual large-function/TU scan-cost mitigations."""

from copy import deepcopy
from unittest.mock import patch

from cgull.analysis_session import analysis_session_for
from cgull.ast_analyzer import CASTParser
from cgull.cfg.construction import clone_structural_cfg
from cgull.cfg.ownership import analyze_ownership_summaries_detailed
from cgull.cfg.summaries import (
    _summarize_output_initialization,
    analyze_function_summaries,
    analyze_function_summaries_detailed,
)
from cgull.rules.dead_store_members import DeadStoresRule


def _parse(source: str):
    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    return ctx


def _topology(cfg):
    return (
        cfg.entry,
        {
            node_id: tuple(event.successors)
            for node_id, event in sorted(cfg.nodes.items())
        },
        dict(cfg.edge_truth),
        {
            edge: (frozenset(add), frozenset(remove))
            for edge, (add, remove) in cfg.edge_facts.items()
        },
        {
            block_id: (
                tuple(node.node_id for node in block.nodes),
                tuple(block.predecessors),
                tuple(block.successors),
                {
                    succ: (frozenset(add), frozenset(remove))
                    for succ, (add, remove) in block.edge_facts.items()
                },
            )
            for block_id, block in sorted(cfg.blocks.items())
        },
    )


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
        cloned = clone_structural_cfg(structural)

    assert cloned is not structural
    assert _topology(cloned) == _topology(structural)
    assert cloned.nodes[structural.entry] is not structural.nodes[structural.entry]
    cloned.nodes[structural.entry].reads.add("__mutated__")
    assert "__mutated__" not in structural.nodes[structural.entry].reads


def test_output_initialization_worklist_matches_prior_semantics():
    ctx = _parse(
        """
        void write_both(int *a, int *b) { *a = 1; *b = 2; }
        void write_one(int *a, int *b) {
            if (*a) { *a = 1; }
            else { *b = 2; }
        }
        void chain(int *a, int *b, int *c) {
            *a = 1;
            write_both(b, c);
        }
        """
    )
    detailed = analyze_function_summaries_detailed(ctx)
    assert detailed.summaries["write_both"].must_initialize_params == {0, 1}
    assert detailed.summaries["write_both"].may_initialize_params == {0, 1}
    assert detailed.summaries["write_one"].must_initialize_params == set()
    assert detailed.summaries["write_one"].may_initialize_params == {0, 1}
    assert detailed.summaries["chain"].must_initialize_params == {0, 1, 2}
    assert detailed.summaries["chain"].may_initialize_params == {0, 1, 2}


def test_dead_store_and_ownership_reuse_session_function_summaries():
    ctx = _parse(
        """
        void free(void *);
        void release(int *p) { free(p); }
        int unused(void) {
            int x = 1;
            x = 2;
            return x;
        }
        """
    )
    session = analysis_session_for(ctx)
    baseline = deepcopy(dict(session.function_summaries))

    with patch(
        "cgull.cfg.summaries.analyze_function_summaries_detailed",
        side_effect=AssertionError("session summaries must be reused"),
    ), patch(
        "cgull.cfg.summaries.analyze_function_summaries",
        side_effect=AssertionError("session summaries must be reused"),
    ):
        ownership = analyze_ownership_summaries_detailed(
            ctx,
            call_graph=session.call_graph,
            call_effects=session.semantic_models.call_effects,
            event_cache=session._event_cache(),
            function_summaries=session.function_summaries,
        )
        assert ownership.summaries
        DeadStoresRule().scan_ast("unused.c", ctx)

    assert dict(session.function_summaries) == baseline
    assert analyze_function_summaries(ctx)["release"].freed_params == {0}
