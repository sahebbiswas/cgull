"""Measure default-mode production rule dispatch on many clean source lines.

Run as python -m benchmarks.benchmark_trace_hot_loop on both revisions.
Timings include preprocessing and real regex/hybrid rules, but exclude hashing.
"""
import argparse
import hashlib
import json
import logging
import platform
import statistics
import time

from cgull.engine import _scan_file_content
from cgull.models import AnalysisEngine
from cgull.rules import get_all_rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lines', type=int, default=10000)
    parser.add_argument('--repetitions', type=int, default=5)
    args = parser.parse_args()
    if args.lines < 1 or args.repetitions < 1:
        parser.error('lines and repetitions must be positive')
    logging.disable(logging.NOTSET)
    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('cgull.engine').setLevel(logging.NOTSET)
    rules = [r for r in get_all_rules() if r.rule_id in {'CGULL-001', 'CGULL-014', 'CGULL-018', 'CGULL-024', 'CGULL-015'}]
    source = 'value += 1;\n' * args.lines
    samples, digests = [], set()
    for _ in range(args.repetitions):
        start = time.perf_counter()
        result = _scan_file_content(source, 'source.c', rules=rules, engine_mode=AnalysisEngine.REGEX)
        samples.append(time.perf_counter() - start)
        assert result[5] == 'success' and not result[0], result
        # Duration is the only intentionally varying result field.
        stable = result[:2] + result[3:]
        digests.add(hashlib.sha256(repr(stable).encode()).hexdigest())
    assert len(digests) == 1
    print(json.dumps({'python': platform.python_version(), 'lines': args.lines,
                      'rule_ids': [r.rule_id for r in rules],
                      'invocations_per_scan': args.lines * len(rules),
                      'seconds': samples, 'median_seconds': statistics.median(samples),
                      'semantic_digest': digests.pop()}, indent=2))


if __name__ == '__main__':
    main()
