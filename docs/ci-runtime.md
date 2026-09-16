# CI runtime baseline and profiling

This note records the investigation behind issue #462 and the timing instrumentation kept in the test matrix. The older runtime tables below are historical evidence; the current support policy was updated by issue #495.

## Current support matrix

C-GULL supports Python 3.12 through 3.14. The unit-test matrix runs every supported version on Ubuntu, Windows, and macOS with no Python-version exclusions. This means the retained minimum, Python 3.12, exercises the same multiprocessing scan paths on Windows and POSIX runners.

The unit-test/coverage step remains the dominant CI phase. Pytest runs with `--durations=30` and writes JUnit timing data, and each matrix job has a 20-minute timeout to retain useful headroom for hosted-runner variance without weakening coverage or behavioral gates.

For the benchmark evidence used to choose the Python 3.12 support floor, including worker startup/IPC measurements, peak RSS, dependency compatibility, and the 3.10–3.14 comparison, see [Python support-floor evaluation (#495)](benchmarks/python-version-495.md).

## Historical baseline before #495

The table below is from successful main run `34787647765` on 2026-09-13, when C-GULL still supported Python 3.10 and 3.11. Windows/Python 3.10 was excluded at that time because its `ProcessPoolExecutor` teardown could deadlock.

| Runner | Python 3.10 | Python 3.11 | Python 3.12 | Python 3.13 | Python 3.14 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ubuntu | 7:42 | 7:33 | 5:47 | 5:12 | 2:05 |
| macOS | 7:05 | 6:09 | 7:02 | 4:01 | 1:56 |
| Windows | — | 8:52 | 7:41 | 5:51 | 2:18 |

The values are elapsed time for `Run Unit Tests with Coverage`, not total job time.

## Historical Windows/Python 3.11 outlier

The slowdown that triggered #462 reproduced in two PR #461 runs:

| Run | Result | Windows 3.11 pytest | Linux 3.11 pytest | macOS 3.11 pytest |
| --- | --- | ---: | ---: | ---: |
| `34752932100` | Windows tests failed during the logging-capture cleanup regression | 13:13 | 9:33 | 6:33 |
| `34759466598` | all matrix jobs passed after handler cleanup | 13:36 | 10:48 | 7:27 |
| `34787647765` | later `main` baseline | 8:52 | 7:33 | 6:09 |

On successful run `34759466598`, the Windows/Python 3.11 job took about 14:26 end to end. Its dependency install was about 18 seconds, while pytest plus coverage consumed 13:36; the behavioral corpus, interprocedural corpus, and focused Juliet steps together consumed under 20 seconds. The variance was therefore in the unit-test/coverage phase rather than checkout, dependency installation, or the post-pytest benchmark steps.

The same run showed a strong Python-version effect on Windows: 3.12 took 5:56, 3.13 took 6:49, and 3.14 took 3:17. Python 3.11 was slower on Linux and macOS too, so the data did not support a purely Windows-filesystem or logging-only explanation. Windows amplified the slowdown, while older interpreter lanes were generally more expensive in that sample.

## Multiprocessing subsystem

The test suite exercises real multiprocessing paths repeatedly. Parallel scan coverage appears in `tests/test_engine.py`, `tests/test_scanner.py`, configuration-space tests, parse-diagnostic tests, telemetry tests, compile-database tests, and several issue regressions. `test_parallel_interrupt_terminates_running_workers_promptly` intentionally creates a real `ProcessPoolExecutor`; Windows workers use spawn.

That makes process startup/teardown and work repeated inside spawned scanner processes a concrete subsystem to watch. Coverage instrumentation increases the cost of those interpreter-heavy paths, and hosted-runner variability can materially affect elapsed time. The #495 benchmark therefore treats timing as directional evidence rather than an absolute cross-version performance ranking.

The generic executor teardown safety remains in the scanner even though Python 3.10 is no longer supported. It is defensive process-lifecycle behavior, not a compatibility shim tied to the old support floor.
