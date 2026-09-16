# Python support-floor evaluation (#495)

Issue #495 evaluated whether C-GULL still benefits from supporting Python 3.10 and 3.11 after the representative medium-project benchmark from #486 became available.

## Decision

C-GULL requires **Python 3.12 or newer**.

The decision is based primarily on compatibility and maintenance surface, with benchmark timing used as supporting evidence:

- The identical #486 workload completed with semantic parity and no parser fallbacks on CPython 3.10 through 3.14.
- Python 3.12 was faster than Python 3.10 in all four sampled file/TU and serial/parallel benchmark arms. The two-worker startup/IPC residual also fell from 50.1 ms to 41.6 ms in file mode and from 30.2 ms to 24.4 ms in TU mode.
- Python 3.11 has no dependency or analyzer-compatibility requirement unique from 3.12+. In this one-shot hosted-runner sample it was slightly faster than 3.12, so dropping 3.11 is **not** justified as a speed claim; it reduces the supported/CI surface and establishes 3.12 as the practical baseline.
- Python 3.10 alone required the `tomli` compatibility dependency. Python 3.12+ can use the standard-library `tomllib` path unconditionally.
- The retained minimum is exercised by the main CI matrix on Linux, Windows, and macOS, including C-GULL's parallel scan tests on both POSIX and Windows.

## Measurement method

Evidence was captured by the `Medium project benchmark` workflow run 35038783631 using C-GULL 0.11.35 at merge revision `c1c3300b8577f42efeea08dfee0656e0625b6ce7`.

Each interpreter ran the same command and generated the same deterministic workload:

```text
python benchmarks/benchmark_medium_project.py \
  --modules 4 \
  --functions-per-module 3 \
  --statements-per-function 4 \
  --modes file,tu \
  --jobs 1,2 \
  --repetitions 1
```

The workload contains 6 files and 166 physical source lines, with SHA-256 `ad082e33d08c868e460b6dbb67b5a5ee951e241aefeb758788cf540bc2ec502b`.

These measurements are **directional**, not a statistically significant runtime ranking. Each Python version used one repetition on a separate GitHub-hosted Ubuntu runner, and the runners were provisioned in different Azure regions. The Python 3.14 `file/jobs=2` sample in particular contains a 316 ms worker startup/IPC residual and should be treated as a hosted-runner outlier rather than an interpreter regression. Compatibility, semantic parity, dependency support, and support-surface reduction are therefore the decisive signals.

## Cross-version wall time and throughput

Each cell is `wall seconds / KLOC/s`.

| Python | file/jobs=1 | file/jobs=2 | tu/jobs=1 | tu/jobs=2 |
| --- | ---: | ---: | ---: | ---: |
| 3.10.21 | 0.553 / 0.300 | 0.427 / 0.388 | 0.476 / 0.317 | 0.396 / 0.382 |
| 3.11.16 | 0.446 / 0.372 | 0.357 / 0.464 | 0.386 / 0.391 | 0.315 / 0.479 |
| 3.12.14 | 0.485 / 0.342 | 0.383 / 0.434 | 0.425 / 0.356 | 0.334 / 0.452 |
| 3.13.15 | 0.275 / 0.603 | 0.240 / 0.693 | 0.239 / 0.631 | 0.232 / 0.650 |
| 3.14.7 | 0.436 / 0.380 | 0.628 / 0.264 | 0.371 / 0.407 | 0.318 / 0.475 |

All five interpreter jobs reported `semantic parity: PASS`; the focused benchmark tests also passed on every version.

## Parallel file-mode detail

The `file/jobs=2` arm exposes the worker-startup/IPC component while keeping the analyzed workload identical.

| Python | Parser (ms) | Project preparation (ms) | Aggregate rule work (ms) | Worker startup/IPC residual (ms) | Peak RSS (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 3.10.21 | 87.3 | 168.4 | 412.3 | 50.1 | 36.3 |
| 3.11.16 | 66.0 | 121.0 | 378.0 | 45.3 | 38.8 |
| 3.12.14 | 72.9 | 131.0 | 416.0 | 41.6 | 39.0 |
| 3.13.15 | 39.6 | 73.0 | 217.6 | 56.8 | 39.7 |
| 3.14.7 | 64.0 | 120.3 | 378.4 | 316.4 | 41.4 |

`aggregate rule work` is CPU-like aggregate activity and can overlap in parallel mode; it must not be added to wall-clock phases. Peak RSS is process-lifetime `ru_maxrss` as recorded by the benchmark harness.

## Resulting support policy

After #495:

- package metadata requires Python `>=3.12` and advertises 3.12, 3.13, and 3.14;
- full CI tests 3.12 through 3.14 on Ubuntu, Windows, and macOS;
- the ongoing medium-project benchmark tests the supported 3.12 through 3.14 range;
- `tomli` and the Python 3.10 fallback imports are removed;
- documentation should describe Python 3.12+ as the supported baseline.
