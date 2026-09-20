# Issue #581 benchmark artifacts

Host-local `tu/jobs=1` arm: 4 modules × 160 functions × 12 statements.
Baseline: `origin/main` @ `bb10fb2f02f1`.

| Metric | Before (main) | After (#581) | Delta |
| --- | ---: | ---: | ---: |
| `build_cfg` count | 11028 | 9081 | -1947 |
| `apply_cfg_event_semantics` count | 8432 | 6485 | -1947 |
| `clone_structural_cfg` count | 11677 | 9730 | -1947 |
| `build_cfg` inclusive (s) | 3.916 | 3.693 | -0.223 |
| `clone_structural_cfg` inclusive (s) | 2.364 | 2.206 | -0.158 |
| `project_summary_construction_seconds` | 5.400 | 5.169 | -0.231 |
| `rule_execution_aggregate_seconds` | 20.467 | 19.853 | -0.614 |
| `total_wall_seconds` | 28.337 | 27.398 | -0.939 |

Semantic digests match (`True`).
Finding counts match (`7 == 7`).

Deterministic signal: **-1947** fewer `build_cfg` / `apply` / `clone` invocations from sharing
post-dataflow memory-rule CFGs. Absolute wall time is host-dependent.
