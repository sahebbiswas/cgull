# Logging capture overhead benchmark (issue #459)

This benchmark measures the end-to-end cost of C-GULL diagnostic capture using the vendored Juliet corpus. It is intentionally separate from `benchmarks/run_juliet.py`: the Juliet runner measures detection quality, while `benchmarks/benchmark_logging_overhead.py` repeatedly invokes the real C-GULL CLI so logging bootstrap, multiprocessing transport, JSONL formatting, retention setup, report generation, and teardown are included in the measured run.

## Release target

The release-critical comparison is default WARNING+ automatic capture against the same scan with automatic capture disabled:

```text
regression_pct = (no_capture_throughput - default_capture_throughput)
                 / no_capture_throughput * 100
```

Default capture passes the issue #459 target when the median regression is **strictly less than 2.0%**. TRACE is an explicit opt-in mode and is reported separately; it is not required to meet the 2% default-capture budget.

The throughput metric is the existing scan telemetry metric from issue #367:

```text
throughput_kloc_per_sec = analyzed_lines / 1000 / elapsed_seconds
```

The benchmark does not recompute analysis time from wall time. It records both C-GULL's analysis elapsed time/throughput and subprocess wall-clock elapsed time.

## Comparison arms

Every cycle scans the same isolated corpus copy with the same Python interpreter, rule set, scan mode, worker count, target, and JSON report rendering. Only logging selection changes:

| Arm | CLI delta | Meaning |
| --- | --- | --- |
| `no_capture` | `--no-log` | automatic JSONL capture disabled; normal WARNING threshold otherwise |
| `default_capture` | none | default WARNING+ automatic JSONL capture |
| `trace_capture` | `-vvv` | TRACE+ automatic JSONL capture |

The harness validates that all measured samples report the same `analyzed_lines`. A mismatch aborts the benchmark instead of comparing runs with different analysis work.

## Noise and retention controls

The default configuration uses one warm-up cycle and five measured repetitions per arm. Arm order is shuffled independently for each cycle using a recorded deterministic seed (`459` by default), so one arm does not systematically receive a warmer or colder machine state.

The source Juliet directory is copied once into a temporary workspace before timing starts. Automatic capture therefore lands under the disposable corpus copy, not under the developer's repository. Before and after each run the harness deletes only C-GULL-owned `scan-*.log` files in that workspace. This prevents retention pruning or accumulated capture files from biasing later repetitions without touching unrelated project logs.

Report rendering is equivalent for all arms: each invocation uses `--quiet --format json --output <per-run-file>`. Corpus copying, capture cleanup, and summary rendering occur outside the per-run wall-clock timer.

## Running the reference benchmark

From the repository root with the normal runtime dependencies installed:

```bash
python benchmarks/benchmark_logging_overhead.py \
  --jobs 2 \
  --mode file \
  --warmup 1 \
  --repetitions 5 \
  --output logging-overhead-459.json
```

`--jobs 2` is the reference parallel configuration for this issue. Larger worker counts may be useful on stable dedicated hardware, but comparisons should not mix worker counts.

The JSON artifact records platform, Python version, C-GULL revision, jobs, scan mode, corpus path, analyzed volume, warm-up/measured arm order, every raw sample, medians, default regression, and the informational TRACE regression. The benchmark always exits successfully after a valid measurement even when the 2% target is missed; shared CI runners are too noisy for a hard performance gate, so the pass/miss verdict is data in the artifact rather than a CI failure condition.

## Representative result

The representative parallel measurement for the implementation commit is stored in `docs/benchmarks/logging-overhead-459.json`. Treat it as an informational point-in-time observation, not a universal golden number. Re-run the command above on the intended release/reference hardware before making a release decision from a narrow margin around 2%.
