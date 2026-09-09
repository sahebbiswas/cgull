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
recomputed against the previous round's imports. They stop when all supported
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
native engine to `ProjectSummaryIndex`. Summary import hooks live in
`cgull/summary_imports.py`; the per-domain transfer and lattice remain in their
existing CFG modules. The regression suite in
`tests/test_issue_365_project_summaries.py` covers single-TU parity, caller-side
findings, ownership/escape, provenance/validation, linkage conflicts,
configuration separation, recursive convergence/degradation, and worker parity.
