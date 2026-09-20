# Issue #543: CFG event-fact caching

Measured baseline: `64b6c0b` (main, #542 instrumentation). Measured head:
the event-cache implementation, then version 0.12.14. Raw #542 artifacts are
`before.json` and `after.json`. The final branch is rebased onto `892f661`
(including #546 preprocessor caching and #547 single-walk deallocation discovery) and bumps version to 0.12.15.
These measurements isolate #543 before that rebase; no additional performance
gain from #546 or #547 is attributed to this change. These historical timings
are not a measurement of incremental gains over the final rebased baseline.

## Results

Linux, Python 3.12.14, standard generated workload (18 files, 3,022 physical
lines), jobs=1, three repetitions per mode, fixed `PYTHONHASHSEED=0`, identical
workload path. Measurements ran sequentially without concurrent test runs.
Timings are medians in seconds and are specific to this host.

| Mode | Total before → after | Reduction | Event annotation before → after | Reduction |
| --- | --- | --- | --- | --- |
| file/jobs=1 | 5.535 → 5.338 | 3.6% | 1.102 → 0.554 | 49.7% |
| tu/jobs=1 | 5.641 → 5.339 | 5.3% | 1.237 → 0.557 | 54.9% |

`apply_cfg_event_semantics` invocation counts stay at 2,711 (file) and 2,685
(TU): views are still constructed, but their event facts reuse cached work.
Full semantic snapshots, including findings/fingerprints, match between every
corresponding sample. SCC iteration histograms also match exactly across all
six samples: function summaries 4,656 one-round SCC evaluations, ownership
1,164, requirements 1,164, and value summaries 2,322. A separate regression
covers recursive SCCs requiring multiple rounds.

The interprocedural corpus (24 cases plus its security-fact corpus) and bundled
Juliet corpus (41 cases) produce identical complete JSON reports before/after.
This does not claim a run of the external full upstream Juliet suite.

Total wall-time gains are smaller than the event-pass gains because parsing,
other analyses, and CFG copying remain. Early measurements varied with host
load; these artifacts represent the final implementation, not a universal
latency guarantee. Multiprocessing correctness is exercised by the unit suite;
these timing and SCC totals intentionally use one worker.

## Reproduce

Run the same `measure.py` from each checkout's root, using the same workspace:

```sh
PYTHONHASHSEED=0 python /path/to/measure.py \
  --jobs 1 --modes file,tu --repetitions 3 \
  --workspace /shared/workload --output /path/to/result.json
```

The driver uses #542's benchmark unchanged and appends aggregate SCC iteration
histograms. No instrumentation enters production code.

## Cache contract

Each analysis session owns immutable base facts keyed by AST node and normalized
allocation, deallocation, and reallocation sets. The cache retains its source
map; replacing that map selects a fresh cache. ASTs and maps are read-only for
the session lifetime, as with the existing structural cache.

Only the most recent overlay per compatible key is retained. Its signature
copies the relevant callees' freed/unsafe-dereference parameter sets, return
nullness, and allocation-return flags. It detects in-place summary edits and
does not invalidate for unrelated callee changes. Events without calls directly
reuse the base. CFG views receive fresh mutable sets/dicts.

Function and ownership summary drivers explicitly carry the session cache
through the legacy CFG builder. This preserves event reuse when multiple live
sessions share an AST, without changing ambiguous-owner CFG routing, sharing
session caches, or deduplicating whole-TU summary computations.

## Unit-suite validation

Before rebase, head: 2,687 passed, 1 skipped, 37 subtests passed, 3 failures.
After the first rebase onto `3316746`, head: 2,695 passed, 1 skipped, 37 subtests passed, the same 3 failures.
Unchanged measured baseline: 2,668 passed, 1 skipped, 37 subtests passed, the same 3 failures.
After rebasing onto `892f661`, all 100 focused cache, deallocation, session,
CFG/dataflow, summary-engine, and interprocedural-corpus tests pass.
The failures are environment-dependent multiprocessing diagnostic-transport tests:

- `tests/test_engine.py::TestEngineModes::test_parallel_worker_exception_suppresses_stderr_when_quiet`
- `tests/test_issue_457_parallel_logging.py::TestIssue457ParallelLogging::test_parallel_trace_preserves_worker_pids_and_drains_before_return`
- `tests/test_issue_457_parallel_logging.py::TestIssue457ParallelLogging::test_spawn_worker_error_is_queued_once_and_honors_error_override`

All 19 added cache regressions pass, including recursive fixed-point parity,
custom effects, source maps, mutable-state isolation, and concurrent requests.
