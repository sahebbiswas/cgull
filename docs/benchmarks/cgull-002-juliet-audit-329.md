# CGULL-002 Juliet provenance audit (#329)

## Result

The original symmetric CWE-134 TP/FP and TN/FN result was a benchmark-attribution artifact, not evidence that CGULL-002's legacy 200-line backward scan was failing. PR #341 corrected the upstream Juliet runner to evaluate split-file testcase groups once and allow findings from sibling stages to satisfy the entry wrapper's oracle.

On the corrected group-aware benchmark (workflow run 34063277083, commit `100b6e260f11e0aa4f87d3a263c4739b7931242a`), CWE-134 reports:

| TP | FP | TN | FN | Precision | Recall | F1 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 34 | 20 | 0 | 0.2273 | 1.0000 | 0.3704 |

The old symmetry is therefore gone. Recall is complete in the stratified upstream sample, while precision remains low.

## Root cause

Current CGULL-002 no longer relies primarily on the legacy bounded textual provenance scan in hybrid/AST mode. `cgull/rules/format_string.py` consumes the shared interprocedural value-fact domain and falls back to the syntactic rule only when semantic analysis is unavailable.

The remaining false-positive pressure is caused by conservative gaps in that value domain rather than by the old `MAX_PROVENANCE_LINES` limit:

1. **Split-file Juliet stages are attributed as a group but still scanned independently.** The corrected runner scans every testcase member separately. A flow such as Juliet variant 54 passes `data` from the `54a` source stage through sibling source files before the `54b`/later sink. Because those files are not analyzed as one translation unit, the sink-stage formal parameter has no caller value fact and is conservatively `UNKNOWN`. CGULL-002 intentionally reports an unknown non-literal format argument rather than treating missing cross-file provenance as safe.

2. **Output-mutating library calls are not projected into value facts.** Juliet GoodSource variants commonly establish a safe format string with patterns such as `strcpy(data, "fixedstringtest")`. The value-fact transfer currently updates assignments, declarations, and call result targets, but a standalone call that writes through an output argument does not replace the destination's fact with the literal source fact. This leaves some proven-safe GoodSource paths unknown even within a single file.

The representative Juliet baseline and flow-54 sources confirm both shapes: GoodSource copies a fixed string into `data`, while flow 54 then passes that value through multiple source files before the bad-style `printf(data)` sink.

## Decision

Do **not** suppress CGULL-002 findings merely because format literalness or provenance is `UNKNOWN`. That would hide genuine unsafe helper-sink cases and trade recall for benchmark precision.

Issue #329 is an audit task and can close with no CGULL-002 rule-specific suppression. The appropriate follow-up is to improve the shared value-analysis substrate so it can:

- consume modeled output-parameter effects for literal/trusted copies such as `strcpy`/equivalent APIs; and
- preserve value facts across multi-file/translation-unit call paths used by split Juliet flows.

Once those capabilities exist, rerun the same upstream CWE-134 benchmark and use the numbers above as the corrected baseline.
