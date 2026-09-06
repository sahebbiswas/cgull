# Issue 327: Juliet oracle attribution diagnosis

## Finding

The exact TP/FP and TN/FN symmetry observed for CWE-134 (`CGULL-002`) and CWE-369 (`CGULL-034`) cannot be treated as evidence of rule quality. The generic upstream benchmark oracle is invalid for split-file Juliet layouts because it scans one entry source file at a time and attributes findings only when their line number falls inside the entry file's `bad`/`good*` wrapper function ranges.

Juliet flow variant 54 deliberately passes data through multiple functions in different source files. The `54a` entry wrapper delegates to `54b_badSink` / `54b_good*Sink`; therefore the actual sink is outside the lexical range -- and outside the scanned file -- by construction. A sink finding in a sibling file cannot be credited to the entry wrapper by the current oracle.

## Reproducible sample

`benchmarks/diagnose_juliet_oracle.py` checks a deterministic 50-file sample from the same pinned Juliet 1.3 snapshot used by CI: the first 25 flow-54 entry files for CWE-134 and the first 25 for CWE-369. The diagnostic verifies whether each entry delegates to a sibling `54b_*Sink` stage and reports whether the lexical wrapper range can own that sink.

Run it against the pinned checkout with:

```bash
python benchmarks/diagnose_juliet_oracle.py .juliet-upstream --per-cwe 25
```

Expected interpretation: if the sampled entry files delegate to sibling sink stages, those cases are structurally unscorable by the current single-file lexical oracle. Their FN/TN contributions are harness artifacts, not proof that the corresponding rule missed or suppressed a sink.

## Decision

Issue #328 and any additional CWE-134/CWE-369 rule tuning should remain blocked on a corrected upstream benchmark that scans and attributes complete Juliet testcase groups. The current symmetric full-suite counts should be discarded as a tuning baseline for these two CWEs.

This diagnosis does **not** claim that `CGULL-002` or `CGULL-034` are already correct. It only establishes that the existing full-suite oracle cannot distinguish rule defects from split-file attribution failures for the affected flow variants.
