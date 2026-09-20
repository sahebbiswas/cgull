"""Run #542 counters plus SCC iteration totals against the checkout in cwd.

Usage (from either checkout, with PYTHONHASHSEED=0):
  python /path/to/measure.py --jobs 1 --modes file,tu --repetitions 3 \
    --workspace /shared/workload --output /path/to/result.json

Iteration totals cover this sequential run across every sample and domain.
"""
import json
from collections import Counter, defaultdict
from pathlib import Path
import sys

sys.path.insert(0, str(Path.cwd()))
from benchmarks import benchmark_medium_project as benchmark
from cgull.cfg.fixed_point import SCCFixedPointEngine

iterations = defaultdict(Counter)
original = SCCFixedPointEngine.run


def measured(self, transfer):
    result = original(self, transfer)
    iterations[type(self.lattice).__name__].update(result.iterations_by_scc.values())
    return result


if __name__ == "__main__":
    args = benchmark.parse_args(sys.argv[1:])
    if args.jobs != (1,) or args.output is None:
        raise SystemExit("Use --jobs 1 and --output for complete iteration accounting")
    SCCFixedPointEngine.run = measured
    try:
        status = benchmark.main(sys.argv[1:])
    finally:
        SCCFixedPointEngine.run = original
    artifact = json.loads(args.output.read_text())
    artifact["scc_iteration_histograms"] = dict(iterations)
    args.output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    raise SystemExit(status)
