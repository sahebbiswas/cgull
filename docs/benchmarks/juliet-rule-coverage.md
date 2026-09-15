# Juliet rule coverage

C-GULL tracks empirical Juliet validation separately from rule metadata. A CWE tag on a rule is not, by itself, evidence that the rule has measured precision or recall.

The machine-readable source of truth is [`benchmarks/juliet/rule_coverage.json`](../../benchmarks/juliet/rule_coverage.json). Every active rule must be classified as one of:

- **`measured`** — the rule is explicitly included in the canonical Juliet `CWE_RULE_MAP` and therefore participates in empirical benchmark outcomes.
- **`not-yet-measured`** — the rule has no canonical rule-specific Juliet measurement yet. Some entries identify likely Juliet families, but those mappings are not counted as evidence until benchmark attribution is wired and validated.
- **`no-Juliet-equivalent`** — the rule is a project or coding-standard policy for which Juliet's bad/good vulnerability oracle is not an appropriate validation source.

CI cross-checks the matrix against the live `RULE_REGISTRY`. Adding or removing a C-GULL rule without updating the matrix fails the test suite. CI also rejects a `measured` claim unless the rule is present in the benchmark's canonical `CWE_RULE_MAP`, preventing documentation from overstating empirical coverage.

The current active registry contains 55 rules. With CGULL-042 measured against CWE-563, 16 are Juliet-measured, 8 are explicitly classified as having no suitable Juliet equivalent, and 31 remain to be measured. Dedicated non-Juliet quality corpora, such as the embedded trust-boundary corpus for CGULL-047, remain valuable regression gates but do not change the Juliet status.

## Extending coverage

When adding Juliet coverage for a rule, first confirm that the selected CWE fixtures actually exercise that rule's semantics rather than merely sharing a broad CWE label. Add the rule to `CWE_RULE_MAP`, add or update rule-specific oracle coverage where required, then change the matrix entry to `measured` with the exact CWE set. The tests will reject partial or inconsistent updates.

For broad Juliet CWE families, use deterministic semantic attribution rather than mapping every testcase to every rule associated with that CWE. Unknown template families should fail closed until their applicability is reviewed.

## Dead-store measurement (CGULL-042)

CGULL-042 is mapped to Juliet CWE-563, but the whole `CWE563_Unused_Variable` directory is not treated as a dead-store oracle. The upstream runner classifies pinned Juliet testcase names by stable template-family markers in `benchmarks/juliet_attribution.py` before a testcase contributes to CGULL-042's denominator.

Dead-store families included for CGULL-042 are:

- `unused_value_*` — an initial value is overwritten before a read.
- `unused_init_variable_*` — a value is written and never subsequently read.
- `unused_global_value_*` — a global's prior value is overwritten before use.
- `unused_static_global_value_*` — a static global's prior value is overwritten before use.
- `unused_parameter_value_*` — a parameter's incoming value is overwritten before use.
- `unused_class_member_value_*` — a C++ class member's prior value is overwritten before use.

Declaration-only families are excluded from CGULL-042 scoring:

- `unused_uninit_variable_*`
- `unused_global_variable_*`
- `unused_static_global_variable_*`
- `unused_parameter_variable_*`
- `unused_class_member_variable_*`

Any future CWE-563 template family that does not match one of these reviewed categories is reported as `unclassified` and excluded rather than silently becoming a CGULL-042 false negative.

The canonical full-family reproduction uses the pinned Juliet 1.3 snapshot at commit `f88433e3443648a17671398797a04ea1f8e1a274`:

```bash
python benchmarks/run_juliet_upstream.py /path/to/juliet-test-suite-c \
  --cwe CWE-563 --all --format markdown
```

The full pinned measurement for issue #481 selected 514 testcase entries. Semantic attribution evaluated 341 entries and excluded 173 declaration-only entries; no entries remained unclassified and no source files failed to scan. The measured CWE-563 result was:

| TP | FP | TN | FN | Precision | Recall | F1 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 170 | 0 | 1154 | 122 | 1.0000 | 0.5822 | 0.7359 |

Known rule-correctness gaps found while preparing this measurement remain out of scope for the benchmark wiring: direct aggregate/member dead stores are tracked by #496, and explicit parameter dead stores are tracked by #497. Measurement records those misses rather than changing CGULL-042 solely to improve its Juliet score.

## Integer conversion measurement

CGULL-049 is measured against the canonical upstream CWE-194, CWE-195, CWE-196, and CWE-197 mappings. See [the sign-extension evaluation](cgull-049-sign-extension-351.md) and [the firmware conversion evaluation](cgull-049-firmware-352.md) for reproduction details, counts, and known limitations. External-call conversion coverage remains tracked separately by #376.
