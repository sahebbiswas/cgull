# Issue #583 benchmark artifacts

Host-local `tu/jobs=1` arm: 4 modules × 160 functions × 12 statements.
Baseline: `origin/main` post-#582 (`benchmarks/results/issue-581/after_count_160.json`).

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

Deterministic signal: public `build_cfg` fanout eliminated on this arm by routing
consumers through session-owned structural CFGs. Apply inclusive time rises because
apply is no longer nested inside `build_cfg`'s inclusive timer. Absolute wall time
is host-dependent and not the primary gate for this change.
