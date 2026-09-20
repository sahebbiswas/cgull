# Structural CFG reuse across rules (#583)

Follow-up to #581 / #582. After annotated memory-rule CFG sharing, the medium-project
matrix still showed substantial public `build_cfg` fanout because many rules and
intra-TU analyzers re-entered that entry point even though structural topology was
already cached.

## Mitigation

Route rule and summary/ownership/integer-range consumers through the TU
`AnalysisSession` structural CFG (`session.cfg` / `session.analysis_cfg`) instead of
the public `build_cfg` wrapper. Effect-annotated memory-rule views remain on the
existing `_ast_cfg_for_function` template cache from #582.

The session also retains the latest pre-dataflow annotated template for each
function. Equivalent effective allocator/deallocator/reallocator sets and callee
summary facts reuse that template; every consumer receives an isolated clone.
The key snapshots mutable summary fields, including truthy non-null guards, and
normalizes omitted effect sets to their built-in defaults. Names absent from a
function cannot invalidate its template; allocator-name identifier uses are
included because they can affect alias classification. Only the latest template
is retained, bounding storage across fixed-point rounds and configuration changes.

Synthetic CFGs that intentionally mutate a `FuncDef` (e.g. chroot path analysis)
continue to use `build_cfg_uncached`.

## Measurement

```bash
PYTHONHASHSEED=0 PYTHONPATH=. python benchmarks/benchmark_medium_project.py \
  --modules 4 --functions-per-module 160 --statements-per-function 12 \
  --modes tu --jobs 1 --repetitions 3 \
  --output benchmarks/results/issue-583/review_after_160.json
```

Compare `build_cfg` / `apply_cfg_event_semantics` / `clone_structural_cfg`
`median_invocation_count` and median end-to-end wall time against the same-host
base commit `2e1a456` and submitted PR commit `13bddb4`. Semantic digests must
match. Pass timers are inclusive and overlap; do not add them together or infer
an end-to-end improvement from wrapper counts alone.

Artifacts: `benchmarks/results/issue-583/`.
