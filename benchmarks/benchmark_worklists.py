"""Stress production CFG worklists; run with python -m benchmarks.benchmark_worklists.

Graph construction and fingerprinting are excluded from timing. No wall-clock
threshold belongs in CI. Compare the JSON from two revisions on the same host.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import platform
import statistics
import time

from cgull.cfg.dataflow import StructuredCFG
from cgull.cfg.model import BasicBlock


def make_graph(shape: str, size: int) -> StructuredCFG:
    cfg = StructuredCFG()
    for _ in range(size):
        cfg.new_node('statement')
    cfg.entry = 1
    if shape == 'linear':
        edges = [(i, i + 1) for i in range(1, size)]
    elif shape in {'branching', 'cyclic'}:
        edges = [(1, i) for i in range(2, size)]
        edges += [(i, size) for i in range(2, size)]
        if shape == 'cyclic':
            # A late null assignment returns through the entry and revisits
            # the broad frontier, exercising dequeue/re-enqueue membership.
            edges.append((size, 1))
            cfg.nodes[size].writes.add('p')
            cfg.nodes[size].null_writes.add('p')
    else:
        raise ValueError(shape)
    # Pre-built single-event blocks isolate analysis from block construction.
    for i, node in cfg.nodes.items():
        cfg.blocks[i] = BasicBlock(i, nodes=[node])
        cfg.node_to_block[i] = i
    for src, dst in edges:
        cfg.nodes[src].successors.append(dst)
        cfg.blocks[src].successors.append(dst)
        cfg.blocks[dst].predecessors.append(src)
    return cfg


def fingerprint(cfg: StructuredCFG) -> str:
    # All block and node facts, including ordering of graph successors.
    def normalize(value):
        if isinstance(value, dict):
            return {str(k): normalize(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
        if isinstance(value, (set, frozenset)):
            return sorted(normalize(v) for v in value)
        if isinstance(value, (list, tuple)):
            return [normalize(v) for v in value]
        if hasattr(value, 'value'):
            return value.value
        return value
    payload = normalize({
        'blocks': {i: asdict(b) for i, b in cfg.blocks.items()},
        'facts': {i: {v: asdict(f) for v, f in facts.items()} for i, facts in cfg.node_facts.items()},
    })
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nodes', type=int, default=10000)
    parser.add_argument('--repetitions', type=int, default=5)
    args = parser.parse_args()
    if args.nodes < 3 or args.repetitions < 1:
        parser.error('nodes must be >= 3 and repetitions >= 1')
    results = {}
    for shape in ('linear', 'branching', 'cyclic'):
        samples, digests = [], set()
        for _ in range(args.repetitions):
            cfg = make_graph(shape, args.nodes)
            started = time.perf_counter()
            cfg.analyze_dataflow(all_vars={'p'}, initial_nonnull={'p'})
            samples.append(time.perf_counter() - started)
            digests.add(fingerprint(cfg))
        assert len(digests) == 1, 'non-deterministic analysis'
        results[shape] = {'seconds': samples, 'median_seconds': statistics.median(samples),
                          'semantic_digest': digests.pop()}
    print(json.dumps({'python': platform.python_version(), 'nodes': args.nodes,
                      'repetitions': args.repetitions, 'results': results}, indent=2))


if __name__ == '__main__':
    main()
