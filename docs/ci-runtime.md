# CI runtime baseline and profiling

This note records the investigation behind issue #462 and the timing instrumentation kept in the test matrix.

## Current baseline

The unit-test/coverage step dominates the matrix. The table below is from successful main run `34787647765` on 2026-09-13; Windows/Python 3.10 is intentionally excluded because its `ProcessPoolExecutor` teardown can deadlock.

| Runner | Python 3.10 | Python 3.11 | Python 3.12 | Python 3.13 | Python 3.14 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ubuntu | 7:42 | 7:33 | 5:47 | 5:12 | 2:05 |
| macOS | 7:05 | 6:09 | 7:02 | 4:01 | 1:56 |
| Windows | — | 8:52 | 7:41 | 5:51 | 2:18 |

The values are elapsed time for `Run Unit Tests with Coverage`, not total job time.

## Reproduced Windows/Python 3.11 outlier

The slowdown that triggered #462 reproduced in two PR #461 runs:

| Run | Result | Windows 3.11 pytest | Linux 3.11 pytest | macOS 3.11 pytest |
| --- | --- | ---: | ---: | ---: |
| `34752932100` | Windows tests failed during the logging-capture cleanup regression | 13:13 | 9:33 | 6:33 |
| `34759466598` | all matrix jobs passed after handler cleanup | 13:36 | 10:48 | 7:27 |
| `34787647765` | later `main` baseline | 8:52 | 7:33 | 6:09 |

On successful run `34759466598`, the Windows/Python 3.11 job took about 14:26 end to end. Its dependency install was about 18 seconds, while pytest plus coverage consumed 13:36; the behavioral corpus, interprocedural corpus, and focused Juliet steps together consumed under 20 seconds. The variance is therefore in the unit-test/coverage phase rather than checkout, dependency installation, or the post-pytest benchmark steps.

The same run also showed a strong Python-version effect on Windows: 3.12 took 5:56, 3.13 took 6:49, and 3.14 took 3:17. Python 3.11 was slower on Linux and macOS too, so the data does not support a purely Windows-filesystem or logging-only explanation. Windows amplifies the slowdown, but the older interpreter lanes are generally more expensive.

## Narrowed subsystem

The test suite exercises real multiprocessing paths repeatedly. Parallel scan coverage appears in `tests/test_engine.py`, `tests/test_scanner.py`, configuration-space tests, parse-diagnostic tests, telemetry tests, compile-database tests, and several issue regressions. `test_parallel_interrupt_terminates_running_workers_promptly` intentionally creates a real `ProcessPoolExecutor`; on Windows those workers use spawn, and the workflow already documents a Python 3.10 Windows teardown deadlock.

That makes process startup/teardown and the work repeated inside spawned scanner processes the concrete subsystem to watch. Coverage instrumentation increases the cost of those interpreter-heavy paths. Runner variability then explains why the same Windows/Python 3.11 lane moved from roughly 13.5 minutes to 8:52 without a change that specifically optimized that lane.

PR #461's logging capture exposed Windows cleanup failures, but it is not sufficient to explain the runtime outlier: after the capture-handler cleanup made the matrix pass, Windows/Python 3.11 still spent 13:36 in pytest. Later main remains slower on 3.11 than 3.14 even though the extreme outlier subsided.

## Timing visibility retained in CI

The matrix now runs pytest with `--durations=30 --durations-min=0.5` and emits JUnit timing data. The Windows/Python 3.11 lane summarizes the top 25 test-case durations in the job summary and as GitHub notice annotations. This makes a future regression attributable to specific tests instead of only a single step-level duration.

The test job timeout is 20 minutes. This does not replace profiling: it gives the measured 14:26 outlier reasonable runner headroom while retaining all supported Python/OS coverage and the slow-test diagnostics above. If the Windows/Python 3.11 lane approaches that ceiling again, use the reported slow cases to decide whether a specific multiprocessing test, teardown path, or repeated scan needs isolation or optimization.
