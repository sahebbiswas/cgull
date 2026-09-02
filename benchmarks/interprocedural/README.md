# Interprocedural regression corpus

This corpus measures C-GULL's current behavior across function boundaries
without depending on Juliet function names or on production changes to the
interprocedural analyzer. Each fixture isolates one semantic case and is
scanned with only its target rule enabled.

Run the deterministic baseline report from the repository root:

```bash
python benchmarks/run_interprocedural.py
```

Use `--format json` for machine-readable results. Reports include overall,
per-rule, security-family, and propagation-scenario counts. The command exits nonzero
for scan failures or regressions in stable expectations. Cases marked
`known_gap` remain visible in the metrics but do not fail CI; a future analyzer
may resolve them without first editing the baseline.

## Coverage

The manifest contains safe and unsafe cases for direct wrappers, multiple
callers, return propagation, output parameters, globals, aliases,
header-defined helpers, recursion, and unresolved calls. Together they cover:

- `CGULL-002`: format-string provenance;
- `CGULL-030`: command provenance;
- `CGULL-044`: memory-copy destination bounds; and
- `CGULL-003`/`CGULL-022`: allocation and ownership lifecycle.

It also records reduced Juliet-style `GoodSource/BadSink` and
`BadSource/GoodSink` results for format strings and command execution.

| Juliet-style variant | Rule | Semantic label | Baseline result |
|---|---|---|---|
| Format `GoodSource/BadSink` | `CGULL-002` | Safe | FP |
| Format `BadSource/GoodSink` | `CGULL-002` | Safe | TN |
| Command `GoodSource/BadSink` | `CGULL-030` | Safe | FP |
| Command `BadSource/GoodSink` | `CGULL-030` | Safe | TN |

## Recorded baseline

| Scope | Cases | Expected + | Expected - | TP | FP | TN | FN | Known gaps |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Overall | 22 | 9 | 13 | 6 | 7 | 6 | 3 | 10 |
| Format strings | 8 | 3 | 5 | 3 | 4 | 1 | 0 | 4 |
| Command execution | 6 | 2 | 4 | 2 | 3 | 1 | 0 | 3 |
| Memory-copy bounds | 2 | 1 | 1 | 0 | 0 | 1 | 1 | 1 |
| Allocation lifecycle | 6 | 3 | 3 | 1 | 0 | 3 | 2 | 2 |

Every baseline mismatch has a reason and a link to the
[interprocedural analysis milestone](../../docs/interprocedural-analysis.md#rule-adoption-priorities)
in `manifest.json`.

## Manifest contract

Each case declares its fixture, scenario, family, target rule, semantic
`vulnerable` label, and `baseline_detected` result. A known gap is required
exactly when those two booleans differ. The runner validates that:

- at least 20 unique fixture cases exist;
- every required scenario and family has both a safe and unsafe case;
- fixture files and rule IDs exist;
- every known gap has a reason and a valid milestone link; and
- the recorded overall, per-rule, and per-family baseline matches the cases.

When behavior changes, remove a `known_gap` after its semantic expectation is
met and update the recorded baseline in the same change. New regressions in
non-gap cases remain blocking.
