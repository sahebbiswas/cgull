# FIFO worklist optimization (#493)

The runtime audit replaces all 23 `pop(0)` calls across 14 analysis modules
with `deque.popleft()`. Seven fixed-point loops that previously checked list
membership now keep a companion `queued` set. Removal happens immediately
on dequeue, allowing a self-loop or back-edge to schedule the node again.
The sets are never iterated to schedule work. Initial ordering, successor
ordering, duplicate handling, integer-range widening counts, sorted SCC
priority queues, and intentional LIFO traversals are unchanged.

## Reproduce

Run both revisions with the same interpreter and dependencies, sequentially
on an otherwise idle host:

```sh
python -m benchmarks.benchmark_worklists --nodes 10000 --repetitions 5
python -m benchmarks.benchmark_medium_project --jobs 1 --modes file,tu --repetitions 3 --output medium.json
```

For the base revision, copy `benchmarks/benchmark_worklists.py` into its
checkout first. The focused benchmark uses production legacy CFG dataflow
on pre-built single-event blocks, excluding graph construction and result
fingerprinting from timings. Linear graphs provide a narrow-queue control;
broad branching graphs stress queue length and duplicate suppression; cyclic
graphs propagate a late null assignment through the entry to revisit the
frontier. Every repetition must produce the same full block/node-fact digest.
These are deliberately extreme queue workloads, not typical C function sizes.

The medium-project benchmark is the unmodified #486 harness with its default
16 modules, 10 functions per module, and 12 statements per function. Compare
complete semantic snapshots (findings, parser status, errors and file counts),
workload hashes, and analyzed line counts across revisions. Activity timings
overlap; do not add phase timings together. No timing threshold is imposed in CI.

## Captured results

Base `a01bfdb`, candidate based on that revision with this change, Python 3.12.14, Linux x86_64. Raw samples, environment, phase timings and semantic snapshots are in [worklists-493.json](worklists-493.json). Runs used the same interpreter and dependencies, without concurrent tests.

| Production CFG workload | Before (s) | After (s) | Speedup |
| --- | ---: | ---: | ---: |
| linear (10,000 nodes) | 0.1331 | 0.1359 | 0.98× |
| branching (10,000 nodes) | 0.5267 | 0.1615 | 3.26× |
| cyclic (10,000 nodes) | 0.9568 | 0.2510 | 3.81× |

Medians of five samples. Full block/node-fact digests match before and after.

| Medium-project mode | Total before / after (s) | Rule analysis before / after (s) | Project summaries before / after (s) |
| --- | ---: | ---: | ---: |
| file/jobs=1 | 7.280 / 7.272 | 5.542 / 5.494 | 0.759 / 0.755 |
| tu/jobs=1 | 7.059 / 7.125 | 5.275 / 5.391 | 0.727 / 0.708 |

Medians of three samples. The 3,022-line medium workload shows no meaningful end-to-end improvement (file mode approximately unchanged; TU mode 0.9% slower). The benefit is concentrated in large, broad worklists; these small functions are dominated by other work. Findings, parser status, file accounting, analysis volume, and workload hashes match exactly across revisions. Parallel timing was not measured because this environment blocks multiprocessing-manager sockets.

## Validation

The full existing suite passed 2,441 tests (one skipped); three multiprocessing logging tests failed because manager socket creation is forbidden in this environment. The two worker-log transport failures also reproduce on the unchanged base; the quiet-stderr failure occurs only in the full suite and passes in isolation on the base. Four new regression tests cover repeatable linear/branching/cyclic convergence and current-node re-enqueue on a self-loop.
