#!/usr/bin/env python3
"""Benchmark issue #308's large/macro-heavy AST extraction path.

This intentionally reports timings instead of enforcing a performance gate;
wall-clock thresholds are too environment-sensitive for CI.  It compares the
legacy regex fallback with the optimized public parser on identical synthetic
input and also reports the normal parser path (including pycparser/pcpp when
installed).
"""

from __future__ import annotations

import argparse
import statistics
import time
from typing import Callable

from cgull.ast_analyzer import CASTParser
from cgull.ast_analyzer.visitor import CASTParser as LegacyCASTParser
from cgull.models import ParseTier


def synthetic_source(function_count: int) -> str:
    parts = [
        "#define ADD_ONE(x) ((x) + 1)\n",
        "#define SELECT(x) ((x) ? ADD_ONE(x) : 0)\n",
        "unsigned long global_before = 1;\n",
    ]
    for i in range(function_count):
        parts.append(
            f"int fn_{i}(int value) {{\n"
            f"    int local_{i} = SELECT(value) + {i};\n"
            f"    return local_{i};\n"
            "}\n"
        )
    parts.append("unsigned long global_after = 2;\n")
    return "".join(parts)


def force_regex(parser):
    parser._try_pycparser = lambda clean_code, defined_syms=None: (
        None,
        False,
        ParseTier.REGEX_FALLBACK.value,
    )
    return parser


def measure(fn: Callable[[], object], repeats: int) -> float:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--functions", type=int, default=5000)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()

    source = synthetic_source(args.functions)
    legacy = force_regex(LegacyCASTParser())
    optimized = force_regex(CASTParser())

    legacy_ctx = legacy.parse(source)
    optimized_ctx = optimized.parse(source)
    if [fn.name for fn in legacy_ctx.functions] != [fn.name for fn in optimized_ctx.functions]:
        raise SystemExit("optimized extraction changed function output")
    if set(legacy_ctx.global_variables) != set(optimized_ctx.global_variables):
        raise SystemExit("optimized extraction changed global-variable output")

    legacy_time = measure(lambda: legacy.parse(source), args.repeats)
    optimized_time = measure(lambda: optimized.parse(source), args.repeats)
    normal_time = measure(lambda: CASTParser().parse(source), args.repeats)

    speedup = legacy_time / optimized_time if optimized_time else float("inf")
    improvement = (1.0 - optimized_time / legacy_time) * 100.0 if legacy_time else 0.0

    print(f"functions: {args.functions}")
    print(f"source bytes: {len(source)}")
    print(f"legacy regex fallback median: {legacy_time:.6f}s")
    print(f"optimized regex fallback median: {optimized_time:.6f}s")
    print(f"regex fallback speedup: {speedup:.2f}x ({improvement:.1f}% faster)")
    print(f"normal parser median (pycparser/pcpp if available): {normal_time:.6f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
