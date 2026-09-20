# Issue #548: residual superlinear scan cost (first mitigation slice)

## Context

#542 (pass counters) and #543 (CFG event-fact cache) are already on `main`.
#544 (whole-TU summary reuse by semantic key) remains open; this slice lands the
default-key reuse that #544 called out for ownership and CGULL-042 consumers,
plus two algorithmic clone/summary fixes implicated by the post-#543 matrix.

## Post-#543 scaling matrix (before this branch)

Deterministic arms with `--modules 4 --modes tu --jobs 1 --repetitions 1`:

| Arm | LOC | Wall (s) | ms/LOC | summaries | clone (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| stmts=12 / funcs=10 | 751 | 1.252 | 1.67 | 16 × 0.171s | 0.062 |
| stmts=120 / funcs=10 | 5071 | 13.547 | 2.67 | 16 × 1.071s | 1.060 |
| funcs=10 / stmts=12 | 751 | 1.222 | 1.63 | 16 × 0.162s | 0.059 |
| funcs=160 / stmts=12 | 11551 | 30.620 | 2.65 | 16 × 5.847s | 2.489 |

ms/LOC still grows with both function size and function count after #543.

### Attribution

- `analyze_function_summaries_detailed` ran **4 times per analyzed C file**
  (session default + ownership + CGULL-042 base + member path), not once.
- `clone_structural_cfg` rebuilt basic-block topology on every analysis view.
- Summary output-initialization used full-sweep chaotic iteration (one sweep
  per hop on straight-line CFGs).
- Cross-TU `project_summary_construction_seconds` (~5.8s on the 160-function
  arm) remains a separate residual domain outside this slice.

## Mitigations in this PR

1. Copy CFG basic-block topology inside `clone_structural_cfg` instead of
   calling `build_basic_blocks()` when the structural source already has blocks.
2. Reuse `AnalysisSession.function_summaries` for ownership analysis and
   CGULL-042 (misra base + member path) when effect inputs match the session
   default — a bounded #544 slice.
3. Replace summary output-initialization fixed-point sweeps with a worklist.

## After matrix (same host / arms)

| Arm | Wall (s) | ms/LOC | summaries | clone (s) |
| --- | ---: | ---: | ---: | ---: |
| stmts=12 | 1.179 | 1.57 | **4** × 0.051s | 0.046 |
| stmts=120 | 13.449 | 2.65 | **4** × 0.387s | 1.666 |
| funcs=10 | 1.171 | 1.56 | **4** × 0.055s | 0.046 |
| funcs=160 | 30.580 | 2.65 | **4** × 2.220s | 1.262 |

Semantic digests match before/after for every arm (`matrix_summary.json`).

### Measured effect

- Summary engine calls on the 4-module matrix: **16 → 4** (1 per file).
- `count_160` summary inclusive time: **5.85s → 2.22s** (−62%).
- `count_160` clone inclusive time: **2.49s → 1.26s** (−49%).
- End-to-end wall on `count_160` is nearly flat on this host (30.62s → 30.58s);
  rule-execution aggregate drops only ~0.4s because preparation / cross-TU
  project summaries and per-function CFG fanout still dominate.

## Residual

- ms/LOC still rises with statements/function and functions/file.
- Remaining hot weight sits in rule CFG fanout (`build_cfg` / `apply` /
  `clone` call volume), cross-TU project summary construction, and any
  non-default effect-registry summary keys still outside the session cache
  (rest of #544).
- Further #548 work should target those domains with the same matrix, not
  re-litigate default summary reuse.

## Reproduce

```sh
PYTHONHASHSEED=0 python benchmarks/benchmark_medium_project.py \
  --modules 4 --functions-per-module 160 --statements-per-function 12 \
  --modes tu --jobs 1 --repetitions 1 \
  --output /tmp/issue-548-count160.json
```

Raw per-arm artifacts: `before_*.json` / `after_*.json`. Aggregated metrics:
`matrix_summary.json`.
