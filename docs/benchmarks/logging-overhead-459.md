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

The harness validates that all measured samples report the same `analyzed_lines`. It also requires `no_capture` to produce no automatic capture file and both capture-enabled arms to produce at least one `scan-*.log` file. A mismatch aborts the benchmark instead of comparing runs with different analysis work or silently measuring a misconfigured capture path.

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

The checked-in reference artifact is `docs/benchmarks/logging-overhead-459.json`. It was produced on a GitHub-hosted Linux runner on 2026-09-14 using Python 3.12.14, `--jobs 2`, file mode, one warm-up cycle, and five measured repetitions per arm. All arms analyzed 984 lines in every measured sample.

| Arm | Median throughput | Median analysis time | Median wall time | Regression vs `no_capture` |
| --- | ---: | ---: | ---: | ---: |
| `no_capture` | 0.112055 KLOC/s | 8.781 s | 9.009 s | baseline |
| `default_capture` | 0.112479 KLOC/s | 8.748 s | 8.982 s | **-0.38% — PASS** |
| `trace_capture` | 0.009239 KLOC/s | 106.504 s | 106.837 s | +91.75% (informational) |

The default WARNING+ arm therefore meets the strict `<2%` target on this reference run. The small negative regression is best interpreted as **no measurable default-capture slowdown on this hosted runner**, not as evidence that logging improves performance. The default arm created one capture file per run but wrote no WARNING+ records for this corpus slice; TRACE created one capture file of 153,747,337 bytes per run.

TRACE overhead is intentionally reported separately because it is opt-in and exercises high-volume diagnostic capture. The reference result is a point-in-time observation, not a universal golden number; re-run the benchmark on intended release/reference hardware before making a release decision from a narrow margin around 2%.
