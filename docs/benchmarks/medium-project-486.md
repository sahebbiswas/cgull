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

## JSON artifact

The artifact records:

- Python, platform, CPU count, C-GULL version, and Git revision.
- Workload file count, physical LOC, generator dimensions, and a SHA-256 workload hash.
- Scan mode, requested worker count, repetition, analyzed physical LOC, unique source LOC, include-expanded analysis volume (`expanded_analysis_lines`), throughput, finding count, parser fallback count, and peak RSS where the platform exposes `ru_maxrss`.
- Stable semantic snapshots containing findings/fingerprints, parser status counts, scan errors, and file accounting.
- Median wall/throughput/phase values plus expanded analysis volume for each `mode/jobs` arm.
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
| `project_preparation_seconds` | Full `prepare_project` wall time, including parse/expansion and summary work. |
| `project_indexing_seconds` | Construction of cross-TU declaration/signature/binding indexes. |
| `project_summary_construction_seconds` | Fixed-point construction of cross-TU summary domains. |
| `rule_execution_aggregate_seconds` | Aggregate per-file analysis duration after scan-local parser/include work is removed. This is CPU-like work and may exceed wall time in parallel runs. |
| `worker_execution_wall_seconds` | Coordinator wall time spent in sequential or multiprocessing file execution. |
| `worker_startup_ipc_collection_residual_seconds` | Worker wall time minus a conservative ideal-compute lower bound; useful as a relative startup/IPC/scheduling/collection signal on the same host. |
| `aggregate_file_analysis_seconds` | Sum of the file summary durations. |
| `total_wall_seconds` | End-to-end `scan_path` wall time measured by the benchmark. |

The activity timings overlap by design. For example, parser and include-expansion time inside `prepare_project` is also contained in `project_preparation_seconds`. Do not sum every timing field and compare it with total wall time. Use the activity fields to locate expensive work and the wall fields to quantify end-to-end improvement.

For the default multi-file HYBRID workload, `prepare_project()` performs parser/include work before sequential or parallel worker execution, and workers receive prepared units. That keeps parser/include activity comparable across `--jobs` arms without adding benchmark-specific IPC instrumentation. A run that degrades out of that prepared path should be treated as a different semantic/degradation baseline rather than compared as an ordinary performance arm.

Production scan telemetry is intentionally unchanged: these hooks exist only inside the benchmark process, avoiding measurement instrumentation overhead during normal C-GULL use.

## Baseline and optimization workflow

The pull-request benchmark workflow runs a compact one-repetition file/TU and jobs 1/2 matrix on Ubuntu for every supported Python release (3.10 through 3.14). Each Python job uploads its own JSON artifact. This cross-version CI run validates benchmark portability and semantic parity; it is not an absolute performance gate.

`medium-project-486-baseline.json` records the first successful Python 3.12 compact run. Its `baseline.production_main_revision` identifies the production scanner source used for the measurement. The PR that introduced the harness changes only benchmark/docs/workflow code plus the package version, so the measured scanner implementation is identical to that `main` revision; the separately recorded capture revision is GitHub Actions' synthetic PR merge commit.

For an optimization PR:

1. Run the standard command on the unmodified base revision and save the JSON artifact.
2. Run the same command on the candidate revision on the same host and Python version.
3. Confirm workload hashes and semantic parity match.
4. Compare `median_wall_seconds`, throughput, expanded analysis volume, and the relevant phase/activity fields.
5. Attach both JSON artifacts to the PR. Avoid claiming a regression/improvement from runs with different workload hashes, Python versions, or machines.
