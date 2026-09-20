# Medium-project end-to-end benchmark (issue #486)

`benchmarks/benchmark_medium_project.py` is the reproducible scan-performance workload for medium-project optimization work. It generates a deterministic C project locally, runs the normal C-GULL scanner, verifies semantic parity, and emits machine-readable JSON with wall time, scan volume, throughput, environment metadata, and phase timing.

The generated project deliberately contains multiple translation units, shared and nested headers, multiple functions per TU, and cross-TU calls. One source file also contains a stable `gets` call so benchmark arms compare a non-empty finding/fingerprint set instead of only comparing an empty result.

## Standard benchmark

From the repository root:

```bash
python benchmarks/benchmark_medium_project.py \
  --modes file,tu \
  --jobs 1,2,4,0 \
  --repetitions 3 \
  --output medium-project-benchmark.json
```

The default generated workload uses 16 source modules, 10 helper functions per module, and 12 arithmetic statements per helper. Use `--modules`, `--functions-per-module`, and `--statements-per-function` only when intentionally defining a different workload; otherwise keep the defaults so before/after artifacts remain comparable.

`--jobs 0` means C-GULL's normal automatic worker selection. Absolute timings depend on the host, so optimization PRs should compare before/after runs on the same machine, Python version, workload hash, scan mode, and job count rather than adding ordinary-CI wall-clock thresholds.

### Larger repeated-work stress preset

Issue #542 adds a deterministic `large` preset with 4 modules and 160 helper functions per module. It is intentionally an additional stress arm rather than a replacement for the standard #486 workload:

```bash
python benchmarks/benchmark_medium_project.py \
  --preset large \
  --modes tu \
  --jobs 1 \
  --repetitions 1 \
  --output medium-project-large.json
```

Use this preset when an optimization is expected to remove repeated CFG, event-semantics, summary, or preprocessor work whose growth is hard to see on the standard workload.

### Residual scaling matrix (issue #548)

After #542/#543, re-run a one-dimension matrix with `--modules 4`, `--jobs 1`, `--modes tu`, and either:

- `--statements-per-function 12,30,60,120` at fixed `--functions-per-module 10`, or
- `--functions-per-module 10,20,40,80,160` at fixed `--statements-per-function 12`.

Record physical LOC, wall time, ms/LOC, and `median_pass_metrics` for `build_cfg`, `clone_structural_cfg`, `apply_cfg_event_semantics`, and `analyze_function_summaries_detailed`. Artifacts and before/after notes for the first mitigation slice live under `benchmarks/results/issue-548/`.
 Explicit `--modules`, `--functions-per-module`, and `--statements-per-function` values override the selected preset, and the artifact records both the resolved dimensions and the preset name.

## JSON artifact

The artifact records:

- Python, platform, CPU count, C-GULL version, and Git revision.
- Workload file count, physical LOC, generator dimensions, and a SHA-256 workload hash.
- Scan mode, requested worker count, repetition, analyzed physical LOC, unique source LOC, include-expanded analysis volume (`expanded_analysis_lines`), throughput, finding count, parser fallback count, and peak RSS where the platform exposes `ru_maxrss`.
- Stable semantic snapshots containing findings/fingerprints, parser status counts, scan errors, and file accounting.
- Median wall/throughput/phase values plus expanded analysis volume for each `mode/jobs` arm.
- Raw `pass_metrics` for each sample and `median_pass_metrics` for each arm, covering invocation counts, inclusive wall activity, calls per analyzed file, and calls per unique generated source-function definition.
- A parity result. Jobs and repetitions must produce identical semantics and expanded volume within a mode; file and TU modes must produce the same findings/fingerprints. File/TU file accounting and expanded volume are intentionally allowed to differ because TU mode does not separately scan included headers as standalone roots.

Expanded volume is recomputed for exactly the roots reported in `file_summaries` immediately after the timed scan, using the same include roots and defined symbols. That second expansion is excluded from `total_wall_seconds`, all phase timers, and the peak-RSS sample so the measurement itself does not inflate the scan being measured.

A parity failure exits with status `2` unless `--no-enforce-parity` is used for diagnosis.

## Phase telemetry

The benchmark reports these timing fields for every arm:

| Field | Meaning |
| --- | --- |
| `file_discovery_seconds` | Complete file-discovery interval, including traversal, candidate filtering, ignore checks, and candidate-list construction. |
| `tu_include_expansion_seconds` | Include/TU expansion activity in project preparation plus any scan-local expansion. |
| `parser_seconds` | AST parser activity in project preparation plus any scan-local parsing. |
| `preparation_wall_seconds` | Non-overlapping preparation wall time, including TU-discovery preparation plus `prepare_project`. Use this for before/after comparisons when work moves between those phases. |
| `independent_preparation_seconds` | Wall time in `prepare_units`, including worker startup and AST transfer. Sequential parsing remains lazy and is included in `prepare_project` instead. |
| `project_preparation_seconds` | Full `prepare_project` wall time, including parse/expansion and summary work. |
| `project_indexing_seconds` | Construction of cross-TU declaration/signature/binding indexes. |
| `project_summary_construction_seconds` | Fixed-point construction of cross-TU summary domains. |
| `rule_execution_aggregate_seconds` | Aggregate per-file analysis duration after scan-local parser/include work is removed. This is CPU-like work and may exceed wall time in parallel runs. |
| `worker_execution_wall_seconds` | Coordinator wall time spent in sequential or multiprocessing file execution. |
| `worker_startup_ipc_collection_residual_seconds` | Worker wall time minus a conservative ideal-compute lower bound; useful as a relative startup/IPC/scheduling/collection signal on the same host. |
| `aggregate_file_analysis_seconds` | Sum of the file summary durations. |
| `total_wall_seconds` | End-to-end `scan_path` wall time measured by the benchmark. |

The activity timings overlap by design. For example, parser and include-expansion time inside `prepare_project` is also contained in `project_preparation_seconds`. Do not sum every timing field and compare it with total wall time. Use the activity fields to locate expensive work and the wall fields to quantify end-to-end improvement.

For the default multi-file HYBRID workload, preparation performs parser/include work before rule execution, and rule workers receive prepared units. Multi-worker preparation returns benchmark-only parser/include activity counters to the coordinator; these are aggregate activity durations, not wall time. TU discovery can now perform most independent work before `prepare_project`, so use `preparation_wall_seconds` to compare complete preparation. A run that degrades out of that prepared path should be treated as a different semantic/degradation baseline rather than compared as an ordinary performance arm.

Production scan telemetry is intentionally unchanged: these hooks exist only inside the benchmark process, avoiding measurement instrumentation overhead during normal C-GULL use.

## Repeated-pass counters

The #542 instrumentation wraps five hot paths only while the benchmark is active:

| Counter | What it measures |
| --- | --- |
| `build_cfg` | Every invocation of the public CFG construction entry point, including cache hits or semantic rebuild paths routed through it. |
| `apply_cfg_event_semantics` | Reapplication of allocation/deallocation/call-summary event semantics to a structural CFG clone. |
| `clone_structural_cfg` | Structural CFG clone operations used to isolate mutable analysis state. |
| `analyze_function_summaries_detailed` | Full detailed function-summary construction passes. |
| `parse_conditional_directives` | Symbolic conditional-directive parse passes over source text. |

Each sample records `invocation_count` and `inclusive_wall_seconds`. The arm summary reports medians plus `median_calls_per_analyzed_file` and `median_calls_per_generated_function`; the latter denominator is the count of unique function definitions emitted by the workload generator, so TU-expanded header functions can legitimately make the ratio exceed one even before other repeated analysis is considered.

Parallel scan workers receive the metrics destination explicitly in the pickled benchmark work item, so collection does not depend on environment changes being inherited by an already-running POSIX forkserver. They write a cumulative benchmark-only snapshot before each work item resolves and again when the process exits, and the coordinator merges the final per-worker snapshots with its own preparation/indexing activity. Each sample records how many worker snapshot files were merged, how many worker PIDs the executor actually created, and whether those counts match. This avoids treating unused configured worker capacity as a missing snapshot. Snapshot-write failures are reported on stderr but never replace the scan result or the scan's original exception; because the expected count comes from the executor rather than the files, a failed write or hard worker-process loss still makes completeness false instead of silently undercounting the arm. The small snapshot writes are benchmark instrumentation and are included in end-to-end wall time, so before/after wall comparisons must use the same harness revision. This keeps `jobs>1` arms from reporting coordinator-only counts. The pass timings are inclusive activity timings: calls can nest, and activity from separate worker processes is aggregated. **Do not add the five pass times together or compare their sum with total wall time.** Use the counts to prove repeated work disappeared, the individual inclusive timers to locate its cost, and `total_wall_seconds` for end-to-end impact.

The wrappers are installed and restored by the benchmark context even when a sample raises. No production telemetry fields or normal scan entry points are modified persistently.

## Baseline and optimization workflow

The pull-request benchmark workflow runs a compact one-repetition file/TU and jobs 1/2 matrix on Ubuntu for every currently supported Python release (3.12 through 3.14). Each Python job uploads its own JSON artifact. This cross-version CI run validates benchmark portability and semantic parity; it is not an absolute performance gate.

Issue #495 used this harness to capture the same workload on Python 3.10 through 3.14 before changing the support floor. The recorded comparison and decision are in [Python support-floor evaluation (#495)](python-version-495.md).

`medium-project-486-baseline.json` records the first successful Python 3.12 compact run. Its `baseline.production_main_revision` identifies the production scanner source used for the measurement. The PR that introduced the harness changes only benchmark/docs/workflow code plus the package version, so the measured scanner implementation is identical to that `main` revision; the separately recorded capture revision is GitHub Actions' synthetic PR merge commit.

For an optimization PR:

1. Run the standard command on the unmodified base revision and save the JSON artifact.
2. Run the same command on the candidate revision on the same host and Python version.
3. Confirm workload hashes and semantic parity match.
4. Compare `median_wall_seconds`, throughput, expanded analysis volume, and the relevant phase/activity fields.
5. Attach both JSON artifacts to the PR. Avoid claiming a regression/improvement from runs with different workload hashes, Python versions, or machines.

The FIFO worklist optimization has a [before/after evaluation (#493)](worklists-493.md).

The disabled TRACE optimization has a [before/after evaluation (#494)](trace-hot-loop-494.md).

Install optional `psutil` to record `sampled_peak_tree_rss_bytes`: the sum of coordinator and live descendant RSS sampled every 10 ms during the timed scan. This includes preparation and rule workers; shared pages are counted per process, and very brief peaks may be missed. The original `peak_rss_bytes` remains the coordinator process-lifetime high-water mark. Without psutil the sampled field is null.

Parallel preparation has a [before/after evaluation (#488)](parallel-preparation-488.md).
