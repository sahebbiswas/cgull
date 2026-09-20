# Whole-TU summary cache (#544)

Measured on Linux x86-64, Python 3.12.14, using the standard #486 workload
(18 generated files, 3,022 physical LOC), one worker, and three repetitions per
mode. Baseline: `8bc0957`; comparison: the #544 working-tree implementation on
that base. The PR was subsequently rebased over the opt-in persistent-cache
change (#545); persistent caching is disabled in this workload.

Run each checkout with its own repository root on `PYTHONPATH`:

```bash
PYTHONPATH="$PWD" python benchmarks/benchmark_medium_project.py \
  --jobs 1 --modes file,tu --repetitions 3 --output result.json
```

| Mode | Summary engine calls | Inclusive summary time (median) | Total wall time (median) |
| --- | --- | --- | --- |
| file | 72 → 36 | 0.639s → 0.453s | 5.011s → 4.883s (2.6% lower) |
| tu | 64 → 32 | 0.686s → 0.502s | 5.078s → 4.795s (5.6% lower) |

The default workload now computes two distinct summary keys per analyzed file,
down from four calls: 72 → 36 in file mode and 64 → 32 in TU mode. The remaining
two keys preserve the different memory-effect sets requested by legacy consumers
and the session's declarative models. Ownership, dead-store-member, MISRA/style,
and custom-memory consumers reach the cache through the shared legacy accessor.

Every before/after semantic snapshot is identical within its scan mode, including
findings/fingerprints, parser statuses, scan errors, and file accounting. Each
artifact also passes its internal repetition/mode parity checks. Absolute wall
time is noisy; call-count reduction is the deterministic performance evidence.
Inclusive pass timings overlap other phase timings and must not be summed.

Raw artifacts: [before](function-summary-cache-544-before.json) and
[after](function-summary-cache-544-after.json).

Validation: eight cache regressions cover equal-content registries, set ordering,
custom memory effects, ownership registry isolation, imported-summary mutation,
fixed-point options, result mutation, concurrency, independent sessions, and late
model installation. The behavioral corpus matches all 477 expected findings
with zero unexpected findings. The full-suite run initially had 2,845 passes,
one skip, and three failures: two worker-log transport failures reproduce on the
unmodified baseline in this environment; the third parallel stderr test passes
in isolation on both baseline and head.
