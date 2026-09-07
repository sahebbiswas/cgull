# CGULL-049 signedness conversion evaluation (#350)

## Scope and requirements

CGULL-049 now detects potentially value-changing signed-to-unsigned and unsigned-to-signed conversions, including equal-width conversions and signed-to-wider-unsigned conversions. It covers casts, declaration initialization, ordinary assignment, and argument binding to known function definitions in the translation unit. Findings carry CWE-195 or CWE-196; width-only narrowing retains CWE-197. The rule's primary metadata CWE remains CWE-197 for compatibility, with all three directions explained in its description.

A source range must fit the destination interval to suppress a finding. This includes constants, safe widening, dominating guards, and early-return rejection. Regression tests cover both interval boundaries, typedefs, reversed comparisons, partial and stale guards, empty branches, unsigned-zero comparisons, exposed-address mutation, and distinct chained casts. Comparisons themselves remain the responsibility of CGULL-033. No automatic fix is offered.

The shared range helper recognizes standard integer maxima, retains destination ranges after unsafe casts, and invalidates exposed-variable facts on calls or indirect writes. It uses the project's existing integer width model; it does not add target ABI configuration or infer implementation-dependent plain-char signedness.

## Reproduction

Measured with C-GULL 0.9.64 on the upstream Juliet 1.3 snapshot used by CI, `arichardson/juliet-test-suite-c` revision `f88433e3443648a17671398797a04ea1f8e1a274`:

```sh
python benchmarks/run_juliet_upstream.py /path/to/juliet \
  --cwe CWE-195 --cwe CWE-196 --all \
  --output signedness.md --json-output signedness.json
```

## Results

Selected testcase entries: 1170
Scanned source files: 1698
Evaluated bad/good functions: 3667
Failed files: 0

| CWE | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-195 | 0 | 0 | 2832 | 768 | 0.0000 | 0.0000 | 0.0000 |
| CWE-196 | 18 | 2 | 47 | 0 | 0.9000 | 1.0000 | 0.9474 |

Overall precision: 0.9000
Overall recall: 0.0229
Overall F1: 0.0447

The machine-readable result is [cgull-049-signedness-350.json](cgull-049-signedness-350.json). Counts use the upstream runner's function-name oracle and split-file grouping; they are function-level detection outcomes, not per-expression accuracy. `--all` selects every entry discoverable by that runner, including C/C++ source families; it does not imply complete C++ semantic support. With no predicted positives for CWE-195, precision is undefined mathematically and displayed as zero by the runner.

## Interpretation and remaining gaps

CWE-195 has **zero observed recall**. Its cases use implicit signed lengths at library calls such as `malloc`, `memcpy`, and `memmove`. CGULL-049's current argument binding resolves function definitions in the translation unit, not signatures from stripped system headers or external library models. Thus the new cast/assignment detection is exercised by the focused regressions, but does not cover the upstream CWE-195 sink shapes. Supporting declaration-only/library signatures is a concrete follow-up, with these 768 bad-function misses as a baseline. This result must not be described as successful CWE-195 detection coverage.

CWE-196 reaches 100% recall with two good-function false positives under the existing intraprocedural range analysis. Remaining precision limitations include unsupported source/expression facts and cross-function range propagation. The implementation does not add compound-assignment conversion analysis, unknown or indirect callee signatures, full arithmetic expression typing, or general alias analysis.

The registry marks CGULL-049 **measured** only for these two upstream families. Measurement is distinct from a quality threshold. CWE-197 remains unmeasured; neither of these families has been added to the vendored focused manifests. Existing focused Juliet and release gates retain their thresholds.
