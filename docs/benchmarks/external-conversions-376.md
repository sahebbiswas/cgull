# External-call conversion validation (#376)

## Scope and focused evidence

The integration corpus lives in `tests/rules/CGULL-049/external_calls/manifest.json`.
It is consumed by the existing `tests/run_corpus.py` infrastructure and by
`tests/test_issue_376_external_conversions.py`. It contains 24 source fixtures:
16 API/source combinations with 14 functions each, plus eight precedence,
degradation, and multi-conversion fixtures. Expected lists retain exact line,
argument column, CWE, and multiplicity; every other location must be clean.
File attribution is checked relative to the scanner's single-file scan root.

| API | Integer parameter (one-based) | Source prototype | Local header | Fallback | Compile database only |
| --- | --- | --- | --- | --- | --- |
| malloc | 1: size_t | malloc_prototype | malloc_local_header | malloc_fallback | malloc_compile_database |
| memcpy | 3: size_t | memcpy_prototype | memcpy_local_header | memcpy_fallback | memcpy_compile_database |
| memmove | 3: size_t | memmove_prototype | memmove_local_header | memmove_fallback | memmove_compile_database |
| strncpy | 3: size_t | strncpy_prototype | strncpy_local_header | strncpy_fallback | strncpy_compile_database |

Each identifier names a directory containing `case.c`. Pointer parameters are
not integer conversions and are not applicable. The matrix-completeness test
compares parameter positions with the actual built-in models.

Each combination exercises signed char/CWE-194 and int/CWE-195, using direct
lengths, a same-type local alias, nonnegative early-return guards, partial upper
bounds, stale guards followed by reassignment, safe constants, and explicit
size_t casts. These are tests of the current type model, not host ABI inference.
CWE-196 and CWE-197 are inapplicable to these size_t destinations for these source
types; `custom_classes` provides appropriate unsigned-to-signed and width-only
narrowing destinations, with a guarded safe counterpart. Its four independent
arguments on one line must remain four distinct findings. `independent_casts`
checks that an explicit conversion is reported once alongside a separate argument.

| Additional fixture | Meaning of expected result |
| --- | --- |
| compatible | Matching redeclarations retain the conversion finding |
| override | Visible int parameter takes precedence over malloc fallback; type-compatible call |
| conflicting | Unresolved conflicting declarations; no safety claim |
| shadow | Local function-pointer binding blocks named fallback; indirect call unresolved |
| unknown_api | Missing signature; no safety claim |
| unknown_width | Opaque typedef has no known scalar width; no safety claim |
| custom_classes | Unnamed fixed parameters; exact CWE-194/195/196/197 and safe guards |
| independent_casts | Two independent CWE-195 conversions, no cast duplication |

Both file/AST and TU/hybrid paths run the complete matrix. Parallel scan parity,
compile-database-only resolution with fallback disabled, and a subsequent unrelated
TU test prevent configuration leakage. Existing #362 tests also verify conflicting
per-TU include roots and explicit-root precedence. Disabling the signature index
removes all eight implicit findings from each API/source fixture while retaining
the two explicit casts. Disabling fallback alone still permits compile-database
headers to resolve the four APIs. The behavioral control retains double-free and
argv-to-command findings with signatures enabled or disabled; #360's registry
separation test also remains green.

Reproduce:

```sh
python -m pytest tests/test_issue_376_external_conversions.py tests/test_issue_359_callable_signatures.py tests/test_issue_360_standard_callable_signatures.py tests/test_issue_362_compile_database_includes.py -q
python tests/run_corpus.py --rule CGULL-049
```

## Pinned upstream before/after

Juliet: `arichardson/juliet-test-suite-c` at
`f88433e3443648a17671398797a04ea1f8e1a274`.
Before: merged #358, `5bb04aaad72786e81fe0cf1da56d1c6835686e2e`, version 0.9.65;
results are the committed corrected [#351 baseline](cgull-049-sign-extension-351.json),
not a new baseline run. After: analyzer revision
`0698a7b316e45f06b86fbd5c78f7696d659f2f9e` (0.10.7).
This validation-only change bumps the package to 0.10.8 without changing detector
semantics. Both measurements retain exact-CWE attribution for CGULL-049.

```sh
git -C /path/to/juliet checkout f88433e3443648a17671398797a04ea1f8e1a274
python benchmarks/run_juliet_upstream.py /path/to/juliet --cwe CWE-194 --cwe CWE-195 --cwe CWE-196 --all --output upstream.md --json-output upstream.json
# Same evaluation with per-entry counts and revision metadata:
python benchmarks/audit_external_conversions.py /path/to/juliet --output docs/benchmarks/external-conversions-376.json
```

The original runner and the per-entry audit independently produced identical
counts. Each selected 2,322 entries, scanned 3,378 source members, evaluated 7,267
bad/good function oracles, and had zero failed files. The machine-readable
[after report](external-conversions-376.json) lists every selected entry and its
counts. Zero failed files does not imply full AST support for C++.

| CWE / measurement | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-194 before | 0 | 0 | 2832 | 768 | 0.0000 | 0.0000 | 0.0000 |
| CWE-194 after | 576 | 1032 | 1800 | 192 | 0.3582 | 0.7500 | 0.4848 |
| CWE-195 before | 0 | 0 | 2832 | 768 | 0.0000 | 0.0000 | 0.0000 |
| CWE-195 after | 576 | 2064 | 768 | 192 | 0.2182 | 0.7500 | 0.3380 |
| CWE-196 before | 18 | 2 | 47 | 0 | 0.9000 | 1.0000 | 0.9474 |
| CWE-196 after | 18 | 2 | 47 | 0 | 0.9000 | 1.0000 | 0.9474 |

Precision with no predicted positives follows the runner's zero convention.
There are no lost existing true positives: CWE-194/195 had none, and CWE-196
retains all 18. Inspecting the connect_socket_malloc_01 cases confirms raw
CWE-194/195 findings at `malloc(data)`, rather than unrelated socket narrowing.

## Remaining limitations and audit

The increase in recall comes with substantial new false positives. External
signature availability exposes conversions whose safety depends on facts the
current range analysis cannot preserve across helper boundaries, pointer/aggregate
aliases, or global control flags. The good-function oracle also counts wrappers
and helpers separately; these are function outcomes, not unique call counts.
This report makes no claim of universal library or C/C++ coverage.

Concrete reproductions:

```c
/* Out-of-scope expression typing miss; #390. */
void expression(int n) { malloc(n + 1); }

/* Range-summary false positive; #389. */
static void sink(short n) { malloc(n); }
void safe(void) { sink(99); }

/* Alias-range false positive despite the direct nonnegative guard. */
void alias(short n) {
    short *p = &n;
    if (n < 0) return;
    malloc(*p);
}
```

The first has no CGULL-049 finding; the latter two report CWE-194. These are
residual reproducers, not waived supported fixtures. General expression typing
is tracked in [#390](https://github.com/sahebbiswas/cgull/issues/390), and bounded
helper range summaries in [#389](https://github.com/sahebbiswas/cgull/issues/389).
Cross-TU summaries remain [#365](https://github.com/sahebbiswas/cgull/issues/365),
and indirect target resolution remains [#366](https://github.com/sahebbiswas/cgull/issues/366).

There is also an evidenced oracle limitation: connect_socket_malloc_44.c and
_45.c contain raw CWE-194 findings at badSink's malloc calls (lines 51 and 55),
yet both record FN because `_function_matches_oracle` excludes the unprefixed
`badSink` name. Their goodSink counterparts do match. Split-file bad oracle
selection also needs review. [#388](https://github.com/sahebbiswas/cgull/issues/388)
owns that correction. Historical metrics are retained here for comparison;
these misses must not be described as missing external signatures.

## Handoff to #352

Use the manifest and exact expected findings as the bounded signature regression
set; use the per-entry JSON to choose upstream budgets after the disclosed oracle
limitations are addressed. #352 retains firmware-priority and workflow/budget
ownership. CWE-197 is covered by custom integration fixtures here but its own
upstream baseline was not evaluated: its registry status remains **not yet measured**.

### Exhaustive recorded FN partition

The per-entry audit partitions each family's 192 recorded FNs as follows:

| Cause | Flow variants | CWE-194 FN | CWE-195 FN | Evidence / boundary |
| --- | --- | ---: | ---: | --- |
| Unsupported C++ forms | 33, 43, 81–84 | 144 | 144 | References, namespaces and class/virtual/lifetime forms; representative 33 has no raw conversion findings |
| Oracle helper-name attribution | 44, 45 | 48 | 48 | Raw badSink findings exist; #388 |
| Missing/conflicting external signature in this upstream selection | — | 0 | 0 | Still tested as unresolved degradation in the focused matrix |

The additional 1,032 CWE-195 false positives occur in flows 02–11 and 13–17.
Unlike CWE-194's zero initializer, CWE-195 starts at -1; impossible/constant-control
branches can retain that negative initializer in the range join. A minimal
`int n=-1; if (1) n=99; malloc(n);` still reports CWE-195.
This is tracked in [#391](https://github.com/sahebbiswas/cgull/issues/391).
The 1,032 shared FP outcomes occur in flows 21, 22, 32, 34, 41, 42, 44, 45,
51–54, 61, and 63–68: global control, pointer/aggregate value flow, and helper
argument/return flow lose safe-source provenance. This is a flow-category audit,
not a claim that every false positive has one identical root cause. Per-entry
counts remain available for focused follow-up; #389 covers bounded direct-helper
ranges and does not claim arbitrary pointer/global alias analysis.
