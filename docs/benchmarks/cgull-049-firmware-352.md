# CGULL-049 firmware prioritization and Juliet gate (#352)

## Firmware-priority contract

CGULL-049 keeps the conversion correctness predicate implemented by the base unsafe-integer-conversion analysis. Issue #352 does not create new findings from hardware-looking names or integer widths. Instead, an existing CGULL-049 finding is promoted from `Medium` to `High` when its write destination has concrete firmware-facing semantics:

- a `volatile` destination object or aggregate, including a volatile global/register-like object; or
- a structure/union bitfield destination.

A deterministic firmware-priority finding receives `FULL` confidence when the underlying finding did not already carry a confidence qualifier. Existing uncertainty is preserved: for example, a plain-`char` CWE-194 finding remains `LIMITED` because target plain-char signedness is still unknown even when the destination is volatile.

Fixed-width types such as `uint8_t`, hardware-sounding typedef names, variable names containing `reg`/`mmio`, and other spelling-only hints do **not** raise severity. This avoids turning ordinary byte storage into firmware findings. Packed-layout spelling is also not guessed: bitfields are the supported aggregate hardware signal until the AST/type layer exposes a reliable packed-layout attribute. CGULL-049 likewise has no rule-local modeled-MMIO sink metadata today, so no name-based substitute is used.

Focused regressions live in `tests/test_issue_352_firmware_conversion_priority.py` and cover volatile objects, volatile aggregates, bitfields, ordinary fixed-width storage, misleading typedef names, and preservation of limited plain-char confidence.

## Canonical Juliet coverage

`benchmarks/run_juliet.py` maps CGULL-049 to all four conversion families it emits:

- CWE-194: unexpected sign extension;
- CWE-195: signed-to-unsigned conversion;
- CWE-196: unsigned-to-signed conversion; and
- CWE-197: numeric truncation.

The coverage registry therefore records CGULL-049 as measured for CWE-194/195/196/197. Matching remains exact by reported CWE for CGULL-049, so a narrowing finding cannot receive credit for a sign-extension oracle.

## Deterministic PR baseline

The PR-time baseline was recorded from PR #483, workflow run `34851781402`, commit `0e950ff0e0197032fd16ab17c0a08a97cd5a2b75`, using the pinned Juliet 1.3 revision `f88433e3443648a17671398797a04ea1f8e1a274`. The runner used the default deterministic flows (`01`, `02`, `04`, `08`, `31`, `54`, `61`) with at most two testcase entries per CWE/flow. The overall run selected 188 testcase entries, scanned 306 source files, evaluated 770 bad/good functions, and had zero failed files.

| Rule | CWE | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CGULL-049 | CWE-194 | 10 | 8 | 26 | 0 | 0.5556 | 1.0000 | 0.7143 |
| CGULL-049 | CWE-195 | 0 | 0 | 34 | 10 | 0.0000 | 0.0000 | 0.0000 |
| CGULL-049 | CWE-196 | 4 | 0 | 11 | 0 | 1.0000 | 1.0000 | 1.0000 |
| CGULL-049 | CWE-197 | 10 | 17 | 17 | 0 | 0.3704 | 1.0000 | 0.5405 |

The zero CWE-195 score is retained as evidence rather than hidden or reclassified. Because a zero metric cannot decrease further, its regression budget separately requires `FP <= 0`; this prevents the currently quiet family from becoming noisier without being noticed.

The machine-readable source of truth is `benchmarks/juliet/cgull-049-regression-baseline.json`.

## Regression budget

`benchmarks/check_juliet_regression.py` compares the current upstream JSON report with the recorded CGULL-049 baseline. Each CWE is evaluated separately and labeled with the rule ID in the gate report. The default allowed absolute drop is `0.02` for precision, recall, and F1. Missing CWE rows, missing metric fields, report-schema drift, failed source scans, and the CWE-195 false-positive count guard all fail closed.

The budget is intentionally per-CWE. An improvement in CWE-196 cannot mask a regression in CWE-197, and overall Juliet quality for unrelated rules does not affect this gate.

### Reproduce the PR-time gate locally

Use the same pinned Juliet checkout as CI, then run only the four CGULL-049 families with the same deterministic selector:

```sh
python benchmarks/run_juliet_upstream.py /path/to/juliet \
  --cwe CWE-194 --cwe CWE-195 --cwe CWE-196 --cwe CWE-197 \
  --per-flow 2 --format markdown \
  --output cgull-049-sample.md --json-output cgull-049-sample.json

python benchmarks/check_juliet_regression.py cgull-049-sample.json \
  --output cgull-049-regression.md
```

The repository PR workflow still benchmarks every currently mapped CWE so it continues to provide the general upstream report; the CGULL-049 gate reads only these four rows.

### Run the full CGULL-049 Juliet families

For a heavier measurement across every discoverable entry in the four families:

```sh
python benchmarks/run_juliet_upstream.py /path/to/juliet \
  --cwe CWE-194 --cwe CWE-195 --cwe CWE-196 --cwe CWE-197 --all \
  --format markdown --output cgull-049-full.md \
  --json-output cgull-049-full.json
```

The `Upstream Juliet Benchmark` GitHub workflow also exposes a manual `full_cgull_049` option. That path has a larger timeout and publishes `juliet-cgull-049-full`; it is intentionally separate from the bounded PR regression gate.
