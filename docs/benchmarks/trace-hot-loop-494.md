# Disabled TRACE overhead (#494)

`engine._scan_file_content` snapshots TRACE enablement once per file, after
logging the scan entry. Both regex and AST rule loops use that boolean.
Default scans therefore make no per-rule TRACE logging calls or argument
attribute lookups. TRACE messages, INFO boundaries, warnings, capture handlers,
and multiprocessing logging setup are unchanged. Logging-level changes between
files take effect on the next file; reconfiguration during a file is not supported
by this snapshot. The instrumentation audit found no other TRACE/DEBUG calls in
token, node, or fixed-point loops.

## Reproduce

Run on both revisions using the same interpreter and dependencies:

```sh
python -m benchmarks.benchmark_trace_hot_loop
python -m benchmarks.benchmark_medium_project --jobs 1 --modes file,tu --repetitions 3 --output medium.json
```

Copy the new focused benchmark into the base checkout first. It exercises the
production scan function with 10,000 clean lines and five real regex/hybrid rules
(CGULL-001, 014, 015, 018, 024): 50,000 rule calls per scan. The selected rules
avoid whole-file rescanning costs that would obscure dispatch overhead. Timings
include preprocessing, masking, and rule bodies; this is not a pure logging
microbenchmark. Five repetitions must yield the same result digest (excluding
duration), with no findings or failures. The #486 benchmark uses its default
18-file, 3,022-line workload and checks complete findings, parser status, errors,
file accounting, and analysis volume. There are no CI timing thresholds.

## Results

Base `ed3762d`, candidate based on that revision with this patch; Python 3.12.14
on the same Linux host and dependencies. Candidate runs preceded base runs;
benchmarks ran sequentially without concurrent tests. Raw samples and complete
semantic snapshots are in [trace-hot-loop-494.json](trace-hot-loop-494.json).

| Workload | Before median (s) | After median (s) |
| --- | ---: | ---: |
| Focused, 50,000 real rule invocations | 0.2646 | 0.2592 |
| Medium file/jobs=1 | 6.934 | 7.089 |
| Medium tu/jobs=1 | 6.856 | 6.953 |

The focused scan improved approximately 2.0%. The full workload provides no
measured end-to-end speedup: file mode was 2.2% slower and TU mode 1.4% slower.
These small differences should not be interpreted as robust performance claims.
The deterministic improvement is removal of disabled per-rule logging calls;
preprocessing and rule execution dominate these timings. Workload hashes,
complete semantic snapshots, expanded analysis volume, and focused result
digests match across revisions. Parallel throughput was not measured.
