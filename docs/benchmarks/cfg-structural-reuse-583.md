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

Synthetic CFGs that intentionally mutate a `FuncDef` (e.g. chroot path analysis)
continue to use `build_cfg_uncached`.

## Measurement

```bash
PYTHONHASHSEED=0 PYTHONPATH=. python benchmarks/benchmark_medium_project.py \
  --modules 4 --functions-per-module 160 --statements-per-function 12 \
  --modes tu --jobs 1 --repetitions 1 \
  --output benchmarks/results/issue-583/after_count_160.json
```

Compare `build_cfg` / `apply_cfg_event_semantics` / `clone_structural_cfg`
`median_invocation_count` against same-host `origin/main` (post-#582). Semantic
digests must match. Absolute wall time is host-dependent.

Artifacts: `benchmarks/results/issue-583/`.
