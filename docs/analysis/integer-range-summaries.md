# Intra-TU integer range summaries

CGULL-049 preserves conservative integer range facts across direct helper calls within one parsed translation unit. The summaries are behavioral range facts; they do not change or replace the callable signature model.

## Supported parameter propagation

A parameter range is propagated into a helper only when all of the following are true:

- the helper has internal (`static`) linkage;
- the helper is called directly by name inside the same translation unit;
- the function designator does not escape through a pointer or other non-call use;
- the helper is not recursive, directly or through a call cycle; and
- every observed direct caller provides a range that can be modeled for that parameter.

Ranges from all supported callers are joined. A constant argument such as `sink(99)` therefore proves `n == 99` in a private helper, while a guarded call such as `if (n >= 0) sink(n);` preserves the proven nonnegative interval. If any caller can supply the full signed parameter range, the joined summary remains unsafe and CGULL-049 continues to report the conversion.

Externally callable helpers do not use same-file callers as a global proof because callers outside the current translation unit may exist. Likewise, an escaped function designator prevents a direct-call-only parameter summary.

## Supported return propagation

Integer return ranges are summarized from modeled return expressions after applying the function return type. Direct call expressions can consume those summaries, and simple local declaration/assignment forms such as `short n = helper();` retain the returned range for subsequent CFG range checks.

The summary builder iterates parameter and return facts to a bounded fixed point so short direct-helper chains can converge. If the bound is reached without convergence, behavioral summaries are discarded and CGULL-049 falls back to the ordinary unseeded intraprocedural range analysis. Baseline guard and constant proofs are therefore retained even when interprocedural convergence is unavailable.

## Pinned Juliet flow 41/42 behavior

Issue #389 was motivated by the Juliet 1.3 snapshot pinned by C-GULL (`arichardson/juliet-test-suite-c` revision `f88433e3443648a17671398797a04ea1f8e1a274`). Focused regressions mirror the relevant CWE-194 `connect_socket_malloc` flow shapes and assert exact CGULL-049 CWE attribution.

Flow 42 is directly covered by this feature: `goodG2BSource` is a `static` same-translation-unit helper that returns the positive value `100 - 1`. The returned interval is propagated through `data = goodG2BSource(data)`, so the good-path `malloc(data)` no longer produces CWE-194. An unsafe source returning an unconstrained signed `short` still produces CWE-194.

Flow 41 has a deliberate residual diagnostic. Juliet declares `CWE194_Unexpected_Sign_Extension__connect_socket_malloc_41_goodG2BSink` with external linkage, even though the generated good path calls it with `100 - 1`. Treating the observed same-file caller as exhaustive would be unsound because another translation unit could call that sink with a negative value. C-GULL therefore retains CWE-194 for the flow-41 sink under the bounded scope of #389. This is the same conservative behavior required for any externally callable helper; the benchmark fixture does not receive a name- or Juliet-specific exception.

## Conservative invalidation and residual limits

Normal CFG invalidation still applies after a summarized parameter enters a function. Reassignment, volatile/static/global instability, address escape, calls that may mutate exposed storage, and indirect writes can discard a fact before it reaches a conversion sink.

The current scope deliberately does not claim:

- cross-translation-unit range propagation;
- indirect-call target range propagation;
- pointer/aggregate alias reasoning;
- arbitrary C or C++ expression summaries;
- context-sensitive per-call cloning of a helper; or
- recursive range solving.

Cross-TU summary sharing and indirect target resolution remain separate interprocedural concerns. CGULL-049 suppresses a diagnostic only when the resulting modeled range proves the conversion safe; helper names such as `good` or `safe` have no semantic effect.
