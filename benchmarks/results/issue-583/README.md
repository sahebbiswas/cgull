# Issue #583 benchmark artifacts

Host-local `tu/jobs=1` arm: 4 modules × 160 functions × 12 statements.

## Original single-sample comparison

The original `before_count_160.json` was copied from
`benchmarks/results/issue-581/after_count_160.json`. Its recorded revision is
`bb10fb2`, not this PR's base commit `2e1a456`; it is retained as historical
evidence, not a controlled measurement of this PR alone.

| Metric | Before (post-#582) | After (#583) | Delta |
| --- | ---: | ---: | ---: |
| `build_cfg` count | 9081 | 0 | -9081 |
| `apply_cfg_event_semantics` count | 6485 | 5187 | -1298 |
| `clone_structural_cfg` count | 9730 | 8432 | -1298 |
| `build_cfg` inclusive (s) | 3.693 | 0.000 | -3.693 |
| `apply_cfg_event_semantics` inclusive (s) | 1.596 | 3.394 | +1.798 |
| `clone_structural_cfg` inclusive (s) | 2.206 | 1.224 | -0.982 |
| `project_summary_construction_seconds` | 5.169 | 5.207 | +0.038 |
| `rule_execution_aggregate_seconds` | 19.853 | 22.278 | +2.425 |
| `total_wall_seconds` | 27.398 | 30.266 | +2.868 |

Semantic digests match (`909ffeb07a21ca33162bb049b18f99f63ac942e6af49483dd5d2bbf6918ce91f`).
Finding counts match (`7 == 7`).

This sample showed higher end-to-end time despite fewer wrapper calls and did
not establish a performance improvement. Inclusive pass timers overlap; changing
their nesting does not itself explain an increase in a callee's inclusive time.
The review follow-up caches equivalent pre-dataflow annotation templates and
compares repeated same-host runs against explicit revisions below.

## Review follow-up: repeated same-host comparison

Each revision ran three repetitions of the same 4 × 160 × 12 workload,
`tu/jobs=1`, Python 3.12.14, `PYTHONHASHSEED=0`. The runs were serial, with no
concurrent test suite. Values below are medians; raw samples and environment
metadata are in the JSON artifacts.

The benchmark recorded local commit `5710ed2`. The identical code tree
`19285cc6b78689133d2ab24014293a6e6def2942` is published as `7f7e9eb`;
the commit identity differs because publication used the GitHub API.

| Metric | Base `2e1a456` | Submitted PR `13bddb4` | Annotation reuse `5710ed2` |
| --- | ---: | ---: | ---: |
| `build_cfg` calls | 7783 | 0 | 0 |
| `apply_cfg_event_semantics` calls | 5187 | 5187 | 649 |
| `clone_structural_cfg` calls | 8432 | 8432 | 9081 |
| `rule_execution_aggregate_seconds` | 23.140 | 23.417 | 22.830 |
| `total_wall_seconds` | 34.148 | 34.424 | 32.307 |
| Median process-lifetime peak RSS (MiB) | 700.5 | 707.4 | 673.3 |

Median wall time fell 6.1% from the submitted PR and 5.4% from its base.
Event annotation calls fell from 5,187 to 649 (87.5%). The tradeoff is
649 extra structural clones to keep cached templates isolated from consumers,
and additional retained graph memory. The cache keeps only one current template
per function, independent of summary-iteration count.

All nine samples have identical semantic digests and seven findings. Timings are
host-local observations, not universal speedup guarantees.

Artifacts: `review_base_160.json`, `review_submitted_160.json`,
`review_after_160.json`. The original single-sample artifacts remain unchanged.

Validation: full local suite reached 89.74% coverage, with 2,907 passed, one
skipped, and three multiprocessing-log failures caused by unavailable sockets.
Both log-forwarding failures reproduce on the unchanged base; the quiet-mode
test passes alone on both revisions. The original PR CI failures and all new
annotation reuse regressions pass.
