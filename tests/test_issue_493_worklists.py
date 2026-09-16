"""Regression coverage for FIFO convergence on wide joins and loop back-edges."""
import pytest

from benchmarks.benchmark_worklists import fingerprint, make_graph
from cgull.cfg.model import Nullness


@pytest.mark.parametrize('shape', ['linear', 'branching', 'cyclic'])
def test_worklist_convergence_is_repeatable(shape):
    cfg = make_graph(shape, 128)
    cfg.analyze_dataflow(all_vars={'p'}, initial_nonnull={'p'})
    expected = Nullness.MAYBE_NULL if shape == 'cyclic' else Nullness.NON_NULL
    assert cfg.blocks[2].nullness_in['p'] == expected
    first = fingerprint(cfg)
    cfg.analyze_dataflow(all_vars={'p'}, initial_nonnull={'p'})
    assert fingerprint(cfg) == first


def test_self_loop_can_requeue_current_block():
    cfg = make_graph('linear', 3)
    cfg.nodes[2].writes.add('p')
    cfg.nodes[2].null_writes.add('p')
    cfg.nodes[2].successors.append(2)
    cfg.blocks[2].successors.append(2)
    cfg.blocks[2].predecessors.append(2)
    cfg.analyze_dataflow(all_vars={'p'}, initial_nonnull={'p'})
    assert cfg.blocks[2].nullness_in['p'] == Nullness.MAYBE_NULL
    assert cfg.blocks[3].nullness_in['p'] == Nullness.NULL
