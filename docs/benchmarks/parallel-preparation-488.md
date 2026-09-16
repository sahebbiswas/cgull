# Parallel project preparation (#488)

## Method

Same Linux x86-64 host and Python 3.12.14, default #486 workload: 16 C
modules, two shared headers, 3,022 physical lines and 3,395 expanded analysis
lines. Three repetitions per TU/jobs arm; table values are medians in seconds.
The host advertises nine CPUs (automatic API selection uses nine workers).

Base scanner: `bc2bc23` (0.12.3). Candidate scanner: `7c34f90` (0.12.4).
The candidate benchmark instrumentation was copied into the base worktree so
both measure the same non-overlapping preparation interval. The production
base scanner was not modified. Preparation includes TU-discovery expansion,
parsing, IPC, project indexing, and fixed-point summary construction.

```bash
python benchmarks/benchmark_medium_project.py --modes tu --jobs 1,2,4,0 \
  --repetitions 3 --output result.json
```

## Wall time

| Jobs | Base preparation | Candidate preparation | Base total | Candidate total | Total speedup over base |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 2.404 | 2.689 | 10.993 | 10.510 | 1.05× |
| 2 | 3.070 | 2.440 | 8.841 | 7.492 | 1.18× |
| 4 | 2.614 | 1.582 | 6.634 | 4.399 | 1.51× |
| auto (9) | 3.505 | 1.496 | 7.042 | 3.665 | 1.92× |

At four workers, complete preparation improved by 39.5% and total wall time by
33.7% compared with the same-worker baseline. Within the candidate, four workers
provide 1.70× preparation speedup and 2.39× total speedup over one worker.
Automatic selection also improves both intervals. Sequential preparation keeps
its original implementation; small changes in that arm reflect host/run
variation. These shared-host measurements are evidence of useful parallelism,
not absolute timing gates or a promise of speedup on every workload.

Both revisions and every arm/repetition have the same workload hash, semantic
digest (including findings/fingerprints, parser/degradation status, scan errors,
and file accounting), and expanded volume. Parity passed.

## Memory and execution choice

Processes isolate Python parser/preprocessor state and avoid the GIL for the
independent work. Source/profile bundles return ASTs once to the coordinator,
before CFG/session caches exist. This deliberately retains the established
coordinator-owned cross-TU fixed point; serialization/startup costs are included
in preparation timing. The measured improvement supports that choice for this
workload, although tiny projects can pay more startup cost than they save.

The submission window contains at most one task per worker. Each task handles
one source's profiles; completed results are merged immediately and released
from the pending set. The retained prepared project still scales with total
input size, while in-flight work scales with worker count and source/profile
bundle size. Compatible TU-discovery results are reused without another pool.

| Jobs | Base tree peak (MiB) | Candidate tree peak (MiB) |
| --- | ---: | ---: |
| 1 | 76.9 | 76.9 |
| 2 | 229.2 | 237.9 |
| 4 | 384.3 | 401.0 |
| auto (9) | 765.4 | 805.3 |

These separate one-repetition captures use the corrected sampler at `ea9d09b`:
10 ms samples of summed coordinator/descendant RSS, with optional psutil 7.2.2.
Shared pages are counted per process, so this is a conservative process-tree RSS
measure, not unique physical memory; brief peaks can be missed. Initial timing
captures had an invalid PID-namespace memory sample, explicitly replaced with
null and documented in their metadata. Their wall timings and coordinator
`ru_maxrss` remain valid. Memory captures independently pass semantic parity.

## Regression validation

- New tests compare jobs 1/2/4/auto findings, parser states, and cross-TU summaries
  in file and TU modes, including multiple profiles, malformed and missing files.
- Tests force reverse completion, enforce the bounded submission window, exercise
  spawn, prove prepared-unit reuse, and inject parser/pool/transport failures.
- 16 targeted preparation/benchmark tests pass. Full-suite run: 2,475 passed,
  one skipped, three logging-related failures caused by this execution sandbox
  denying multiprocessing Manager sockets. Both transport tests also fail on
  base; the quiet-output test passes in isolation on base and candidate.

## Artifacts

- [Base timing](parallel-preparation-488-base.json)
- [Candidate timing](parallel-preparation-488-head.json)
- [Base memory](parallel-preparation-488-base-memory.json)
- [Candidate memory](parallel-preparation-488-head-memory.json)
