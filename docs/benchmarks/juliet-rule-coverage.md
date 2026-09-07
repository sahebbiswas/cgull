# Juliet rule coverage

C-GULL tracks empirical Juliet validation separately from rule metadata. A CWE tag on a rule is not, by itself, evidence that the rule has measured precision or recall.

The machine-readable source of truth is [`benchmarks/juliet/rule_coverage.json`](../../benchmarks/juliet/rule_coverage.json). Every active rule must be classified as one of:

- **`measured`** — the rule is explicitly included in the canonical Juliet `CWE_RULE_MAP` and therefore participates in empirical benchmark outcomes.
- **`not-yet-measured`** — the rule has no canonical rule-specific Juliet measurement yet. Some entries identify likely Juliet families, but those mappings are not counted as evidence until benchmark attribution is wired and validated.
- **`no-Juliet-equivalent`** — the rule is a project or coding-standard policy for which Juliet's bad/good vulnerability oracle is not an appropriate validation source.

CI cross-checks the matrix against the live `RULE_REGISTRY`. Adding or removing a C-GULL rule without updating the matrix fails the test suite. CI also rejects a `measured` claim unless the rule is present in the benchmark's canonical `CWE_RULE_MAP`, preventing documentation from overstating empirical coverage.

At the time this matrix was introduced, the active registry contains 48 rules (`CGULL-001` through `CGULL-048`): 14 are Juliet-measured, 6 are explicitly classified as having no suitable Juliet equivalent, and 28 remain to be measured. Dedicated non-Juliet quality corpora, such as the embedded trust-boundary corpus for CGULL-047, remain valuable regression gates but do not change the Juliet status.

## Extending coverage

When adding Juliet coverage for a rule, first confirm that the selected CWE fixtures actually exercise that rule's semantics rather than merely sharing a broad CWE label. Add the rule to `CWE_RULE_MAP`, add or update rule-specific oracle coverage where required, then change the matrix entry to `measured` with the exact CWE set. The tests will reject partial or inconsistent updates.
