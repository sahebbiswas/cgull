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

The summary builder iterates parameter and return facts to a bounded fixed point so short direct-helper chains can converge. If the bound is reached without convergence, no behavioral summaries are exposed.

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
