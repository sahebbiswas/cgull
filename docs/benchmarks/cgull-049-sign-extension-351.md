# CGULL-049 unexpected sign extension (#351)

## Detection contract

CGULL-049 reports CWE-194 when a potentially negative narrow signed integer is widened. Narrow means smaller than `int` in the existing integer width model: signed char, short, int8_t, int16_t, and equivalent typedefs/qualified types. Explicit casts, declaration initializers, ordinary assignments, and direct parameter binding to known function definitions are covered. Ordinary int/long widening and unsigned narrow-source widening remain clean.

This is a byte/protocol-data review heuristic. Widening a negative signed value can be intentional and value-preserving; the analyzer cannot infer protocol intent from its type alone. Findings explain the potential sign extension and request manual review, without offering an automatic fix. Widening a narrow signed value to an unsigned destination produces one CWE-194 finding. Other signedness conversions retain CWE-195/CWE-196; width-only narrowing retains CWE-197. Distinct nested conversions can still report separately.

A proven nonnegative source range suppresses CWE-194. Tests include exact boundaries, constant provenance, reversed and early-return guards, partial/stale guards, exposed-address mutation, and unsigned-zero comparisons. C character constants such as `'A'` are treated as `int`, not narrow signed objects; portable ASCII character values can also prove safe initialization.

## Plain char and target uncertainty

The current analyzer has no target plain-char signedness setting. It does not infer signedness from the machine running C-GULL. A plain-char widening therefore receives a manual-review CWE-194 finding with `LIMITED` confidence and a message explicitly stating that sign extension depends on the target's unknown plain-char signedness. Explicit signed/unsigned char types and typedefs retain their known signedness.

Values in the portable nonnegative plain-char interval (0 through the signed-char maximum in the existing width model) are safe. Pre-conversion range facts from high-bit or negative plain-char writes are discarded, because the stored value need not retain that sign. A later nonnegative guard can still prove safety. Unsupported multi-character constants and non-ASCII execution encodings are not assigned speculative constant values.

Casting through the corresponding unsigned narrow type prevents a CWE-194 widening finding. The separate same-width signed-to-unsigned conversion may still produce a CWE-195 review; the two checks describe different conversion steps.

## Reproduction

The evaluation uses C-GULL 0.9.65 and the upstream Juliet 1.3 snapshot pinned by CI: `arichardson/juliet-test-suite-c` revision `f88433e3443648a17671398797a04ea1f8e1a274`.

```sh
python benchmarks/run_juliet_upstream.py /path/to/juliet \
  --cwe CWE-194 --cwe CWE-195 --cwe CWE-196 --all \
  --output sign-extension.md --json-output sign-extension.json
```

The runner selects every discoverable entry for these families, using function-name bad/good oracles and split-file grouping. Counts are function-level outcomes, not per-expression accuracy. Selection includes C/C++ source files; it does not imply complete C++ semantic support.

## Benchmark attribution

Both the focused and upstream runners require the exact reported CWE for CGULL-049. This rule covers several conversion directions, so matching its rule ID alone can credit a CWE-197 narrowing finding as a CWE-194 sign-extension detection. Regression coverage now prevents that attribution error. Other rules retain their existing multi-CWE mapping behavior.

An initial run using the older rule-only attribution counted 192 CWE-194 true positives. Inspection found narrowing reports at socket-input assignments, rather than sign-extension reports at the intended sink. The results below use the corrected attribution and supersede that preliminary number. They also remeasure CWE-195/CWE-196 under the same attribution policy; CWE-197 remains explicitly unmeasured.

## Corrected results

Selected testcase entries: 2322
Scanned source files: 3378
Evaluated bad/good functions: 7267
Failed files: 0

| CWE | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-194 | 0 | 0 | 2832 | 768 | 0.0000 | 0.0000 | 0.0000 |
| CWE-195 | 0 | 0 | 2832 | 768 | 0.0000 | 0.0000 | 0.0000 |
| CWE-196 | 18 | 2 | 47 | 0 | 0.9000 | 1.0000 | 0.9474 |

Overall precision: 0.9000
Overall recall: 0.0116
Overall F1: 0.0229

The machine-readable report is [cgull-049-sign-extension-351.json](cgull-049-sign-extension-351.json). The runner displays precision as zero when there are no predicted positives; mathematically it is undefined in that case. CWE-197 remains **not yet measured**, so no precision/recall/F1 is claimed for that family.

## Interpretation and remaining work

CWE-194 and CWE-195 each have **zero observed upstream recall**, with 768 missed bad-function oracles per family. The implemented cast/assignment/known-parameter behavior is covered by focused regression and behavioral corpus tests, but the upstream cases use external library length conversions such as malloc, memcpy, memmove, and strncpy. Current binding does not resolve those external signatures. The 192 CWE-194 matches from the older rule-only attribution were all removed by requiring CWE-194 findings, and must not be cited as sign-extension detection quality.

A concrete follow-up is declaration-only and standard-library parameter-signature support, evaluated against this corrected baseline. The rule does not add compound assignments, implicit arithmetic promotions, general expression typing, target ABI configuration, or general alias analysis. It also cannot distinguish intentional signed widening from protocol intent solely from a narrow type.

CWE-196 retains 18 true positives, two false positives, and no false negatives (precision 90%, recall 100%, F1 0.9474). The new conversion-attribution policy leaves those measured counts unchanged from #350.

The empirical registry's measured status records that evaluation occurred; it is not a minimum-quality claim. These three upstream families are not vendored focused fixtures. Existing focused Juliet thresholds remain unchanged.
