# Project-level direct-call summaries

A multi-file AST or hybrid scan imports supported function summaries from other
successfully parsed translation units in the same scan. This is automatic in
both file and TU modes and with sequential or parallel workers:

```sh
cgull scan src/ --engine ast --jobs 4
```

For example, if `callee.c` defines `release(p)` by calling `free(p)`, a call to
`release(p)` followed by a dereference in `caller.c` can produce CGULL-022 even
though the definition is outside the caller's TU. Scanning only `caller.c`
cannot infer that body-derived effect. A declaration alone never creates a
callee summary.

## Supported facts

The project index supplies inputs to the existing TU summary engines and rule
queries. It does not combine source ASTs into a synthetic translation unit or
introduce different transfer semantics.

| Domain | Cross-TU facts |
| --- | --- |
| Function/memory | Return nullness, allocation returns, freed parameters, unsafe dereferences, and output initialization |
| Ownership | Definite/possible free, modeled ownership transfer and escape, consumption, allocation returns, and returned parameter aliases |
| Value | Return provenance, format literalness, and argument-to-return dependencies |
| Security | External return/output provenance, parameter/output dependencies, validator effects, and sink requirements |

These remain the existing bounded, context-insensitive summaries. Importing a
summary does not make unsupported constructs inside its body analyzable.

## Demand-driven analysis requirements

Project summaries are selected from the enabled rule set before project
analysis starts. Built-in rules declare the analysis facts they consume using
`analysis_requirements`; the scanner computes the transitive dependency closure
once per compatible project group and evaluates only the resulting project
summary domains.

The requirement vocabulary is defined in `cgull.analysis_requirements`:

- `function-summary`
- `ownership-summary`
- `value-summary`
- `security-summary`
- `size-facts`
- `pointer-range-facts`

Dependencies are centralized there as well. Ownership summaries require
function summaries, while pointer-range facts require size facts and value
summaries. Size facts are currently TU-local, so a size-only rule does not by
itself force a project summary index.

Custom rules may explicitly declare a requirement set on their concrete class,
for example:

```python
class MyRule(BaseRule):
    analysis_requirements = frozenset({"value-summary"})
```

For compatibility and safety, a custom or third-party rule whose concrete class
does not declare `analysis_requirements` receives the legacy all-requirements
behavior. Built-in metadata is deliberately not inherited by an unannotated
third-party subclass; subclasses must opt in explicitly if they want a smaller
set. Unknown requirement names also fall back conservatively to all analysis.

`ProjectSummaryIndex.domain_evaluations` exposes scan-local per-domain evaluation
counts for tests and performance instrumentation. A zero count means the domain
was not evaluated, rather than merely producing an empty summary map.

## Resolution and configuration identity

Each scan owns a fresh index. Inputs are partitioned by the exact requested
macro map (including values and undefinitions), ordered canonical include
roots, and semantic-model registry equality. Profiles never share analysis
sessions. Different compile-database include contexts remain separate, even
when that conservatively prevents an otherwise valid cross-file match.

Within a compatible partition:

- A named external function must have exactly one definition. Duplicate
  definitions, including repeated header definitions or duplicates in a single
  TU, are not selected arbitrarily.
- `static` definitions and declarations have TU-local linkage, including a
  definition whose earlier declaration supplied `static`. Same-named static
  helpers never become external candidates.
- Local definitions retain the established intra-TU resolution path.
- Visible prototypes must agree structurally with the callee's declarations.
  Parameter names do not matter; referenced typedef and aggregate definitions
  are checked. Shadowed function names, conflicting declarations, or uncertain
  type compatibility prevent import. This deliberately does not implement all
  of C's compatible-type rules.
- Only directly named calls import definitions. Function-pointer resolution
  remains the separate bounded intra-TU feature.

The scan only indexes discovered, non-ignored roots and their normal include
expansions. Fallback-parser bodies are not exported. The index does not search
for libraries or files outside the scan target.

## Recursion, degradation, and cost

The index processes a graph of TU dependencies in deterministic
callee-before-caller SCC order. Acyclic components are evaluated once.
Recursive cross-TU components use snapshot rounds, with the existing TU engines
recomputed against the previous round's imports. They stop when all required
summary maps stabilize, with a limit of 64 rounds. If the limit is reached,
all imports and exports of that component are discarded; downstream callers
retain ordinary unresolved-call behavior. Partially converged safety proofs
are never published.

The scanner parses each file/profile once during project preparation and
reuses that parsed input during rule checking. TUs without a cross-file
relationship retain lazy summary construction. Rule workers receive only their
own file's prepared contexts, not the entire project index. Preparation adds
work and retains parsed TUs in memory until worker dispatch; it is included in
total scan elapsed time, not counted as additional scanned source lines.

Ambiguity, incompatible declarations, preparation failures, and convergence
limits are available through `scanner.project_diagnostics`. They are also
logged as warnings in normal scans; quiet scans suppress their warning output.
Single-file and text scans retain the existing TU-only behavior.

## Current boundaries and extension points

Cross-TU actual-to-formal entry-state propagation, integer/size/range summaries,
whole-program globals, virtual dispatch, link-time aliases, dynamic loading,
and arbitrary pointer analysis are outside this layer. In particular, security
summaries containing global-name relationships are not imported: those names
need a separate linkage-aware object index before they can be used safely.
Parameter-based provenance and validator summaries remain supported.

A new summary domain can use the same compatible symbol bindings and add its
native engine to `ProjectSummaryIndex`, then register its declarative dependency
in `cgull.analysis_requirements`. Summary import hooks live in
`cgull/summary_imports.py`; the per-domain transfer and lattice remain in their
existing CFG modules. The regression suites in
`tests/test_issue_365_project_summaries.py` and
`tests/test_issue_489_project_summary_requirements.py` cover single-TU parity,
caller-side findings, ownership/escape, provenance/validation, linkage
conflicts, configuration separation, recursive convergence/degradation,
worker parity, demand-driven domain selection, and legacy-rule compatibility.


## Parallel preparation

Multi-worker scans prepare independent sources in processes before deterministic
project indexing and summary evaluation. This includes the include expansion
used to classify orphan headers in TU mode. Each process owns its parser and
preprocessor; scan configuration callbacks and custom rules stay in the
coordinator during preparation. Compatible scan-local prepared units are reused.

At most one source task per worker is outstanding. A task prepares that source's
requested profiles and returns its ASTs before CFG/session caches are built.
Completed units are merged by source/profile identity, and indexing proceeds in
sorted source order regardless of completion order. AST serialization is an
explicit cost of retaining the existing coordinator-owned cross-TU fixed point.
Memory remains proportional to the retained project plus at most one in-flight
source/profile bundle per worker; it is not a constant-memory project analysis.

Ordinary expansion/parse failures retain conservative degradation. Pool/transport
failures retry the affected source locally so healthy TUs can continue. `jobs=1`
retains sequential preparation and lazy parsing. See the [performance evaluation](../benchmarks/parallel-preparation-488.md)
for measured startup/IPC and memory tradeoffs.
