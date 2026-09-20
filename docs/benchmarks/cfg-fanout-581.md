# Residual CFG fanout / project-summary mitigation (#581)

Follow-up to #548 / #579 and #544 / #580. Residual cost after those changes sits
in rule CFG fanout (`build_cfg` / `apply` / `clone`) and cross-TU
`project_summary_construction`.

## Mitigation (first slice)

1. **Shared memory-rule CFGs** — `_ast_cfg_for_function` caches the
   post-dataflow CFG on the AST context keyed by function name, effect sets, and
   completed summary serialization so equivalent memory rules reuse one view.
2. **Basic-block topology copy on clone** — `clone_structural_cfg` copies block
   topology from the source when present instead of calling
   `build_basic_blocks()` on every analysis view. This overlaps the clone fix
   in #579; when both merge, keep a single implementation.
3. **Project-summary session reuse** — `ProjectSummaryIndex._evaluate` keeps the
   per-TU `AnalysisSession` (and its call graph / structural CFGs) across
   domains and convergence rounds. When imports change it clears only derived
   summary caches rather than constructing a replacement session.

## Measurement

```bash
PYTHONHASHSEED=0 PYTHONPATH=. python benchmarks/benchmark_medium_project.py \
  --modules 4 --functions-per-module 160 --statements-per-function 12 \
  --modes tu --jobs 1 --repetitions 1 \
  --output benchmarks/results/issue-581/after_count_160.json
```

Compare `clone_structural_cfg` inclusive time and
`project_summary_construction_seconds` against same-host `origin/main`.
Semantic digests must match. Absolute wall time is host-dependent.

Artifacts: `benchmarks/results/issue-581/`.
