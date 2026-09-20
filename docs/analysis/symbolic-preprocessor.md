# Symbolic preprocessor analysis

C-GULL has two deliberately separate preprocessing layers:

| Layer | Purpose | Configuration semantics |
| --- | --- | --- |
| **Concrete preprocessing** | Produce source for AST-backed analysis by expanding macros and selecting active branches. The strongest parser tier uses `pcpp` before `pycparser`; resilient fallback tiers may strip directives when full preprocessing cannot be used. | One concrete macro environment at a time. |
| **Symbolic preprocessor analysis** | Preserve the complete conditional-directive tree and reason about which branches are possible, impossible, redundant, or Boolean-equivalent without selecting one active configuration. | A conservative Boolean abstraction over the configuration space. |

The symbolic layer lives in `cgull.preprocessor`. It does **not** replace concrete preprocessing, macro expansion, or parser fallback behavior. See [AST preprocessing and coverage guarantees](../preprocessing.md) and [Analysis model](../analysis-model.md) for the concrete path.

## CPRE dependency and ownership boundary

Issue #436 replaces the long-term in-tree adaptation of CPRE-derived symbolic
preprocessor functionality with an explicit, versioned dependency on the
[`cpre`](https://github.com/sahebbiswas/cpre) package.

- **Supported range:** `cpre>=0.11.0,<0.12` (first release with the public
  symbolic expression, lossless conditional-structure, and exact proof/witness
  APIs required for migration).
- **Import boundary:** analyzer code must use `cgull.preprocessor.cpre_api`
  (or top-level `cpre` symbols that module re-exports). Do not import
  `cpre.model`, `cpre.expressions`, `cpre.structure`, `cpre.proofs`,
  `cpre.robdd`, `cpre.parser`, or `cpre.cpre`.
- **cpre owns:** shared IR, structure, and exact Boolean reasoning plus their
  compatibility contract.
- **C-GULL owns:** CGULL-054/055 and related diagnostics, CLI/reporting, scan
  orchestration, and configuration-profile reduction policy layered on those
  primitives.

This release only declares the dependency and the pinned API entry point; the
local `cgull.preprocessor` implementation remains the active engine until later
#436 slices migrate call sites through `cpre_api` and remove superseded modules
after parity coverage.

Two accepted naming differences are recorded for the future adapter (from
cpre's symbolic migration readiness gate):

- witness definedness category: C-GULL `defined` ↔ cpre `macro_defined`
- structural diagnostic codes: `invalid_macro` ↔ `malformed_macro_directive`,
  `unexpected_tokens` ↔ `trailing_directive_text`,
  `misplaced_directive` ↔ `unmatched_directive`,
  `unterminated_block` ↔ `unterminated_conditional`

## Focused CLI: `cgull preprocessor`

Use the focused command when you want to inspect conditional compilation without running the full security rule set:

```bash
cgull preprocessor src/
cgull preprocessor src/ --verbose
cgull preprocessor src/ --json
```

The target may be one supported C/C++ source file or a directory. Directory discovery honors configured path exclusions, `--ignore-file`, and repeated `--ignore-pattern` values. `-c/--config` selects an explicit `.cgull.toml` or `pyproject.toml`.

Default human-readable output reports only semantically interesting entries: `dead`, `redundant`, and `simplified`. `--verbose` also includes `unchanged` branches and their reachability. Structural parser diagnostics are always shown.

`--json` emits schema version 1 with:

- `target`, per-file `entries`, structural `diagnostics`, I/O `errors`, and a run `summary`;
- for each entry: directive `kind`, semantic `status`, `reachability`, source `location`/`range`, `original_condition`, `simplified_condition`, `context_condition`, `effective_condition`, and `contextual_simplification`;
- summary counts for all analyzed entries, even when unchanged entries are omitted from the non-verbose `entries` arrays.

For example, this source:

```c
#if FEATURE_A
int a(void);
#elif FEATURE_A && FEATURE_B
int b(void);
#endif
```

reports the `#elif` as `dead`, because reaching it already requires `!FEATURE_A`.

The command returns exit status 2 for discovery, UTF-8/I/O, or conditional-structure errors. A successfully proven dead/redundant/simplified condition is analysis output, not a CLI failure by itself.

## Supported directives and Boolean abstraction

The conditional parser recognizes all eight standard/C23 conditional forms used by C-GULL:

`#if`, `#ifdef`, `#ifndef`, `#elif`, `#elifdef`, `#elifndef`, `#else`, and `#endif`.

It preserves nesting, source ranges, comments, continuations, and malformed structure. Conditions model:

- bare macro truth such as `#if FEATURE` as a `Variable("FEATURE")`;
- definedness such as `#ifdef FEATURE` as a distinct `Defined("FEATURE")`;
- integer constants and Boolean `!`, `&&`, `||` with parentheses;
- more complex value-bearing C expressions such as `VERSION >= 3` or `BOARD_ID == PROD_BOARD` as opaque `Predicate` atoms.

These atom kinds are intentionally independent. In particular, `Variable("X")`, `Defined("X")`, and `Predicate("X")` are not interchangeable. The symbolic engine does not infer C integer relationships between opaque predicates: `VERSION >= 3` and `VERSION < 3` remain independent Boolean atoms unless a future analysis explicitly supplies integer reasoning.

This conservatism is important for firmware-style configuration code: C-GULL can prove Boolean relationships that follow from the conditional structure it models, but it does not pretend to solve arbitrary preprocessor arithmetic.

## Contextual and effective conditions

C-GULL analyzes a branch in the context in which that branch can actually be reached.

For each `#if` / `#elif` / `#else` chain:

1. the **context condition** combines enclosing parent branches with the negation of earlier siblings;
2. a conditional branch's **effective condition** is that context AND the branch's own condition;
3. an `#else` branch's effective condition is simply the remaining context.

For example:

```c
#if PLATFORM_A
#  if PLATFORM_A && DEBUG
int trace_enabled;
#  endif
#endif
```

The inner condition is analyzed under the parent context `PLATFORM_A`. Under that context, `PLATFORM_A && DEBUG` can be simplified to `DEBUG`.

Sibling ordering matters too:

```c
#if WIFI
int wifi_impl;
#elif WIFI && DIAGNOSTICS
int diagnostic_impl;   /* effective condition: !WIFI && WIFI && DIAGNOSTICS */
#endif
```

The second branch is unreachable even though `WIFI && DIAGNOSTICS` is satisfiable in isolation.

## Semantic diagnostics

The focused CLI uses four statuses. Scanner-facing rules expose the same semantic analysis as low-severity control-flow findings.

### Dead / unreachable

A branch is `dead` only when its effective Boolean condition is provably unsatisfiable. Scanner rule `CGULL-054` reports these as **Low** severity, CWE-561 findings that require review.

```c
#if FEATURE
int enabled;
#elif FEATURE && DEBUG
int impossible;        /* dead: FEATURE is already false here */
#endif
```

### Redundant

A branch is `redundant` when the remaining context already guarantees its condition. `CGULL-054` also reports this case as **Low** severity.

```c
#if FEATURE
#  if FEATURE
int nested;            /* redundant: parent already guarantees FEATURE */
#  endif
#endif
```

### Simplified

A condition is `simplified` when C-GULL proves a smaller Boolean expression equivalent in the branch context. Scanner rule `CGULL-055` reports this as **Low** severity guidance.

```c
#if FEATURE || (FEATURE && DEBUG)
int enabled;           /* simplify to FEATURE */
#endif
```

Context can also enable a simplification that is not valid globally:

```c
#if FEATURE
#  if FEATURE && DEBUG
int trace;             /* simplify to DEBUG under FEATURE */
#  endif
#endif
```

### Unchanged

`unchanged` means the branch is modeled and no dead/redundant/smaller equivalent proof was produced. It is hidden by the focused CLI unless `--verbose` is used.

Structural errors such as a missing condition, duplicate `#else`, branch after `#else`, or missing `#endif` are separate parser diagnostics, not semantic statuses.

## Witness configurations

`derive_branch_witnesses(tree)` can produce one deterministic Boolean witness for each satisfiable branch. A witness contains truth assignments to the atoms needed to satisfy that branch's effective condition.

Witness terms keep their meaning explicit:

- `macro_value` — truth of a bare macro-value test;
- `defined` — macro definedness;
- `predicate` — truth of an opaque value-bearing expression.

For an opaque condition such as `VERSION >= 3`, a witness may say only that the predicate must be true. It does **not** invent `VERSION=3` or any other integer macro value.

Witness status is one of `satisfiable`, `unreachable`, `unsupported`, or `limit_exceeded`. Malformed conditions are unsupported instead of guessed.

A witness is evidence inside C-GULL's Boolean abstraction. It is **not** proof that every Boolean assignment corresponds to a realizable C-preprocessor macro environment, and it is not an enumeration of all possible macro-value combinations.

## Configuration-space reduction

Normal configuration exploration is controlled by the scan CLI, for example:

```bash
cgull scan . --config-strategy baseline
cgull scan . --config-strategy one-at-a-time
cgull scan . --config-strategy pairwise
cgull scan . --config-strategy exhaustive --exhaustive-threshold 8
```

C-GULL can reduce generated profiles by modeled branch behavior before scanning equivalent variants. For each generated profile, it computes which modeled conditional branches can be active and keeps one deterministic representative for each distinct branch signature.

Important semantics:

- reduction applies to generated/derived profiles; explicit user-supplied profiles remain authoritative and bypass it;
- known macro values choose known Boolean edges;
- opaque predicates remain free, so reduction asks whether a branch **can** be active without fabricating an integer value;
- a profile that reaches no modeled conditional branch is still retained as a valid class because unconditional source must still be scanned;
- if malformed structure or Boolean resource limits prevent a safe equivalence proof, C-GULL falls back to exact flag-map deduplication rather than dropping a potentially distinct configuration.

The reduction therefore removes work only when equivalence is safe under the symbolic model. It does not claim complete equivalence across all C-preprocessor arithmetic or macro-expansion behavior.

See [Configuration reference](../configuration.md#configuration-space-inputs) and [Analysis model](../analysis-model.md#preprocessor-configuration-profiles) for scan-facing configuration controls.

## Resource limits and conservative fallback

Exact Boolean queries use a reduced ordered binary decision diagram (ROBDD) with deterministic default limits per analysis:

- at most 64 distinct Boolean atoms;
- at most 100,000 BDD nodes;
- at most 500,000 work units.

When a public Boolean query reaches a limit, it fails in the non-assertive direction:

- satisfiability assumes the expression may be satisfiable, so C-GULL will not create a dead-code proof from exhaustion;
- implication/equivalence return no proof, so C-GULL will not claim redundancy or exact equivalence;
- witness derivation reports `limit_exceeded`;
- exact simplification falls back to the local algebraic simplifier;
- profile reduction falls back to exact flag-map deduplication.

Malformed conditions similarly stop proof across the affected sibling chain instead of guessing later branch reachability.

## Interaction with `pcpp` and parser fallback tiers

Symbolic analysis reads the original conditional-directive structure. It does not need `pcpp` to decide which branch is active because it deliberately does not choose an active branch.

AST-backed security rules have a different job: they need parseable source for a concrete configuration. Their strongest tier uses `pcpp` plus `pycparser`; if preprocessing cannot be used, C-GULL may fall back to directive stripping plus `pycparser`, then to lighter extraction. Those fallback tiers can reduce structural precision, and known security-critical losses are surfaced as coverage degradation rather than silently described as full analysis.

The two layers therefore complement each other:

- concrete preprocessing answers "what source is active under this configuration?";
- symbolic analysis answers "what can be proven about the conditional configuration space without selecting one configuration?".

## Firmware-style example

Consider a configuration-heavy module:

```c
#if defined(BOARD_A) && LOGGING
void log_backend(void);
#elif defined(BOARD_A) && LOGGING && USB_LOG
void usb_log_backend(void);     /* dead: earlier branch already covers it */
#endif

#if defined(BOARD_A)
#  if defined(BOARD_A) && TRACE
void trace_backend(void);       /* simplify to TRACE under the parent context */
#  endif
#  if defined(BOARD_A)
void board_init(void);          /* redundant nested test */
#  endif
#endif

#if FW_VERSION >= 3
void modern_protocol(void);     /* opaque value-bearing predicate */
#else
void legacy_protocol(void);
#endif
```

C-GULL can reason exactly about the Boolean relationships among `defined(BOARD_A)`, `LOGGING`, `USB_LOG`, and `TRACE`. It retains `FW_VERSION >= 3` as an opaque predicate and can reason about its truth as one atom, but it does not infer integer ranges for `FW_VERSION`.

## Nodes and atom identity

All nodes are frozen, hashable dataclasses. `Conjunction` and `Disjunction` own
tuples of operands (iterable constructor inputs are copied). Leaf payloads and
child types are validated on construction.

| Type | Meaning |
| --- | --- |
| `Constant(bool)` | Boolean truth; `TRUE` and `FALSE` are shared conveniences |
| `Variable(name)` | Boolean truth of a macro's value |
| `Defined(name)` | Whether the macro is defined |
| `Predicate(text)` | An opaque value-bearing C expression |
| `Negation(operand)` | Logical negation |
| `Conjunction(operands)` | Logical conjunction; empty means true |
| `Disjunction(operands)` | Logical disjunction; empty means false |

`Variable("X")`, `Defined("X")`, and `Predicate("X")` are distinct atoms. Unlike
the prototype, the IR preserves definedness separately: a macro defined as zero
is defined but false in a value test. There are no inferred relationships among
different atoms. In particular, `N > 3` and `N <= 3` are independent opaque
predicates until a later analysis supplies integer reasoning.

Predicate text is preserved exactly, including whitespace inside string
literals. Token-aware lexical normalization belongs to a future parser, not
this IR. Macro names must be ASCII C identifiers.

## Normalization and formatting

```python
from cgull.preprocessor import (
    Variable, Defined, Predicate, conjunction, disjunction, negate,
    format_expression, expression_to_dict, expression_from_dict,
)

a = Variable("A")
condition = disjunction(a, conjunction(a, Predicate("VERSION >= 3")))
assert condition == a  # absorption
assert format_expression(conjunction(Defined("X"), negate(Variable("X")))) == (
    "defined(X) && !X"
)
assert expression_from_dict(expression_to_dict(condition)) == condition
```

`normalize` (also exposed as `simplify`) recursively folds constants and double
negation, flattens associative operators, removes duplicates, detects direct
complements, applies absorption, and sorts commutative operands using a typed
structural key. `negate`, `conjunction`, and `disjunction` normalize their results.
Raw dataclass constructors preserve tree structure; compare normalized nodes
when operand ordering should not matter. Normalization is not a complete Boolean
equivalence or satisfiability check; it does not distribute operators or build a
BDD.

`format_expression` normalizes before rendering C-style operators. Parentheses
preserve operator precedence and isolate opaque predicates when embedded. The
display string is not an identity or serialization format: distinct atom types
can have the same display text.

## Enumeration and serialization

- `expression_atoms` returns a set of typed atoms in the original tree, even if
  normalization would remove them. `ordered_atoms` returns these unique atoms
  in deterministic structural order, suitable for a future BDD variable order.
- `expression_predicates` returns a set of opaque texts without extracting
  identifiers from them.
- `expression_to_dict` normalizes and emits JSON-compatible tagged objects.
  `expression_from_dict` validates exact fields and types, rejects unknown kinds
  with `ValueError`, and returns a normalized expression.

The tags are `constant` (`value`), `variable`/`defined` (`name`), `predicate`
(`text`), `not` (`operand`), and `and`/`or` (`operands`, an array). Every object
contains `kind`. For example:

```json
{"kind": "not", "operand": {"kind": "defined", "name": "FEATURE"}}
```

Formatting, normalized structure, ordered atoms, and serialized output are
stable across operand permutations and Python hash seeds. Python's numeric
`hash()` values themselves are process-dependent and must not be persisted.

## Conditional-directive tree

Issue #421 adds `parse_conditional_directives(source)` to the same package:

```python
from cgull.preprocessor import parse_conditional_directives

tree = parse_conditional_directives('#if FEATURE\nint x;\n#else\nint y;\n#endif\n')
block = tree.blocks[0]
assert block.branches[0].body_range.text(tree.source) == 'int x;\n'
assert block.branches[1].directive.kind == 'else'
assert not tree.diagnostics
```

The parser supports `if`, `ifdef`, `ifndef`, `elif`, `elifdef`, `elifndef`,
`else`, and `endif`. It retains every recognized conditional directive in
`tree.directives`, even misplaced directives, in source order. `tree.blocks`
contains top-level blocks; each block owns ordered `branches` and an optional
`endif`. A branch points back to its `block`, owns nested `children`, and each
nested block points to its containing branch through `parent`. Construction is
iterative, so conditional nesting does not depend on Python's recursion limit.
The mutable structural containers use identity equality to avoid recursive
comparison through parent links; directive and location records are frozen and
compare by value.

`tree.source` retains the input exactly. All ranges are half-open Python string
(character, not byte) offsets with one-based original line/column coordinates;
a tab occupies one character column. Call `range.text(tree.source)` to recover
text without reparsing. Directive ranges include the complete physical logical
line, including indentation, continuations, comments and its final newline.
Body ranges extend from the end of the opening/branch directive to the beginning
of the next sibling or closing directive, and include nested blocks. Block
ranges include their opening and closing directives. Unterminated ranges extend
to EOF. LF and CRLF line endings are retained.

Each directive carries condition tokens with original ranges, so even a token
split by a backslash continuation maps back to its original physical lines.
`condition_text` is the exact source slice between the first and last condition
tokens (including intervening comments/continuations); `logical_condition` is
the spliced, comment-masked expression with outer whitespace removed.
`condition_range` is absent when there are no condition tokens. The original
full directive range always retains leading/trailing comments and whitespace.
Comments and quoted literals, including C++ raw strings, cannot create spurious
directives. Other preprocessing directives are left in the source/body ranges.

`condition` recognizes macro truth, `defined`, integer constants, parentheses,
and Boolean `!`, `&&`, and `||` using C precedence. More complex value-bearing
subexpressions remain opaque `Predicate` atoms; ternary/comma expressions are
not incorrectly decomposed into Boolean clauses. Excessively deep expression
syntax also remains opaque. Expression nodes preserve operand order; consumers
can explicitly normalize them with the expression API. This is not a full C
expression syntax checker or macro expander, and opaque predicates carry no
inferred integer semantics.

Recoverable `StructureDiagnostic` records provide `code`, `message`, and an
original `source_range`. Codes cover `misplaced_directive`, `duplicate_else`,
`branch_after_else`, `unterminated_block`, `missing_condition`, `invalid_macro`,
and `unexpected_tokens`. Diagnostics are ordered by source position. Branches
after an `else` are retained with errors; unmatched closing/branch directives
remain in the flat directive list. Invalid macro conditions have no symbolic
expression. Lexical errors outside conditional structure and general C
expression validity are outside this API's diagnostic contract.

The parser does not choose active branches, rewrite source, diagnose redundant
conditions, or participate in the scanner's concrete preprocessing path.
