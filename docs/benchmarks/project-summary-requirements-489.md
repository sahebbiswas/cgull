# Demand-driven project-summary benchmark (#489)

Issue #489 makes project-level summary construction depend on the requirements
of the enabled rules instead of evaluating every supported summary domain on
every cross-TU round.

## Workload and method

The benchmark reuses the deterministic medium-project generator and phase
timing from #486. `benchmarks/benchmark_project_summary_requirements.py` runs
two sequential file-mode arms against the same generated source tree:

1. the default rule set, which requires all four project-summary domains; and
2. `CGULL-002` (`FormatStringRule`) only, which requires only the value-summary
   domain after #489.

The same helper is copied into the pull request's base checkout and run there,
so the before/after comparison uses identical workload generation and timing
instrumentation. The workflow verifies the workload SHA and the semantic digest
for each arm before reporting timing deltas.

The compact CI measurement uses 4 modules, 3 functions per module, 4 generated
statements per function, one repetition, Python 3.12.14, and Ubuntu 24.04. The
generated workload contains 6 files and 166 physical lines with SHA-256
`ad082e33d08c868e460b6dbb67b5a5ee951e241aefeb758788cf540bc2ec502b`.

## Result

| Rule arm | Base domains | Head domains | Base project-summary time | Head project-summary time | Reduction |
| --- | --- | --- | ---: | ---: | ---: |
| Default rules | function, ownership, value, security | function, ownership, value, security | 0.048886 s | 0.046966 s | 3.9% |
| `CGULL-002` only | function, ownership, value, security | value | 0.048186 s | 0.011433 s | 76.3% |

Semantic digests matched before and after for both arms. The default arm retained
all four domains and therefore serves as the no-domain-elision control. The
restricted arm omitted three of four project domains and reduced measured
project-summary construction time by 76.3%, closely tracking the amount of
summary work removed on this workload.

The restricted arm's end-to-end wall time also decreased from 0.151352 s to
0.112915 s. The default arm changed from 0.508189 s to 0.484960 s; with a
single compact CI repetition that difference should be treated as noise rather
than a claimed general speedup.

## Reproduction

Run a more stable local measurement with multiple repetitions:

```sh
python benchmarks/benchmark_project_summary_requirements.py \
  --modules 16 \
  --functions-per-module 10 \
  --statements-per-function 12 \
  --repetitions 3 \
  --output project-summary-requirements.json
```

For pull requests, `.github/workflows/medium-project-benchmark.yml` also runs a
compact base/head comparison on Python 3.12 and uploads both JSON artifacts.
The comparison fails if workload hashes or semantic digests differ, and asserts
that the restricted head arm evaluates only the value project-summary domain.

## Interpretation

The optimization changes scheduling, not transfer semantics. Default scans that
need every project-summary domain should not be expected to become materially
faster from #489 alone. The intended improvement appears when a configuration
enables a narrower rule set: unneeded domains are not evaluated or included in
cross-TU convergence, while legacy/custom rules without explicit requirement
metadata remain on the conservative all-analysis path.
