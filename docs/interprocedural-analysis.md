# Interprocedural Analysis Milestone

## Status and motivation

This document scopes a milestone, not a single pull request. C-GULL's CFG is
flow-sensitive within a function and already computes a small fixed-point set
of intra-file function summaries (`freed_params`, return nullness, and whether
a function returns an allocation). It does not yet carry general value
provenance, taint, bounds, initialization, or ownership facts through calls.
Consequently, statement-shaped rules cannot relate a source in one function to
a sink in another.

The proposed implementation issues are available as a schema-compatible batch
in [interprocedural-analysis-issues.md](interprocedural-analysis-issues.md).

The milestone should generalize the existing summary mechanism rather than add
a second interprocedural engine. The first useful boundary is one expanded C
translation unit (TU). The translation-unit scan work in
[#215](https://github.com/sahebbiswas/cgull/pull/215) and recursive include
expansion in [#196](https://github.com/sahebbiswas/cgull/pull/196) make
functions from the source root and expanded headers available in one AST;
project-wide, cross-TU analysis is a later milestone.

## Definition of "interprocedural" for the first milestone

For each successfully parsed translation unit, C-GULL will:

1. Build a direct-call graph for functions with definitions in the expanded
   TU, retaining source provenance from the TU line map.
2. Analyze each function with the existing CFG and compute reusable summaries
   to a fixed point over call-graph strongly connected components. Recursion is
   supported through conservative convergence, not call-stack expansion.
3. Propagate facts from actual arguments to formal parameters, from return
   expressions to receiving variables, and from callee side effects back to
   caller arguments.
4. Evaluate rule sinks using the facts at the call site. Analysis is
   flow-sensitive within a function but initially context-insensitive between
   functions: one conservative summary is shared by all call sites.
5. Treat unresolved calls, indirect calls, unsupported expressions, and parser
   fallback as `unknown`. Unknown must never be interpreted as safe. Findings
   affected by unknown facts should retain the current conservative behavior
   and expose limited confidence/reason metadata where reporting permits it.

The initial abstract facts should cover:

- provenance/taint classes (trusted constant, external/untrusted, mixed,
  unknown), with source, sanitizer, and sink descriptors;
- string-format literalness;
- buffer extent and size constraints where statically known;
- initialization and nullness;
- allocation identity and ownership state (allocated, escaped, freed, or
  unknown), including parameter side effects; and
- return-value relationships such as "returns parameter 0" or "returns a
  newly allocated value".

Facts should attach to stable symbolic locations, not only variable spellings,
so simple aliases and struct members can be represented. Version one may be
field-sensitive for named struct members and index-insensitive for arrays.
Pointer arithmetic, unions, arbitrary casts, variadic forwarding, callbacks,
and function pointers remain conservative unknowns unless explicitly modeled.

## Architecture

### Shared analysis model

Extend `FunctionSummary` into a rule-neutral summary composed of effects and
value relationships. Keep rule policy outside the CFG package: the analysis
answers questions such as whether an argument can be untrusted, whether a
destination has a known lower-bound capacity, or whether a callee may free an
argument; a rule decides whether that fact warrants a finding.

Add explicit call events to `CFGEvent` (callee identity, actual arguments,
optional result target, and source location). The current construction code
already recognizes value-producing calls and applies the small memory
summaries; this should become the single transfer point for all summary facts.

A per-TU analysis session should own the AST, call graph, summaries, and query
API. It must be computed once per TU/configuration profile and shared by rules.
Today several rules independently call `analyze_function_summaries`; retaining
that pattern would multiply the cost and could let rules observe inconsistent
models.

### Summary computation

Use a finite lattice and monotone transfer functions so fixed-point iteration
terminates. Process call-graph SCCs bottom-up, iterating recursive SCCs until
stable. Summaries should describe:

- which output/return facts depend on each parameter or global;
- parameter/global side effects, including initialization, writes, frees,
  escapes, and possible bounds changes;
- sinks reached from each input, including the argument position and required
  safety property; and
- certainty (`must`, `may`, `unknown`) and compact provenance sufficient to
  explain a finding.

Do not serialize whole CFG paths into summaries. Bound provenance and merge it
at joins to avoid exponential growth. Cache summaries by expanded-TU identity,
configuration profile, analyzer version, and relevant configured source/sink
models.

### Library and external-call models

Provide declarative models for standard C/POSIX functions and configured
project wrappers. Models should identify sources, sinks, sanitizers, allocation
and deallocation effects, output parameters, format argument positions, and
size relationships. An absent model means unknown, not no effect. Custom banned
function configuration remains independent of these semantic models.

## Rule adoption priorities

1. **CGULL-002 (format strings):** highest-confidence first consumer. Track
   literals and untrusted values through parameters, returns, assignments, and
   wrappers to distinguish a constant format from a caller-controlled one.
2. **CGULL-001 (banned functions):** split policy from dataflow. APIs that are
   unconditionally prohibited (`gets`, insecure temporary-file APIs, or a
   user-configured ban) must still be reported regardless of provenance.
   Data-dependent overflow variants may use destination capacity and source
   extent to refine severity/confidence, but a "safe" source alone must not
   silently bless an intrinsically unbounded API such as `strcpy`. This avoids
   tuning the security policy solely to Juliet naming variants.
3. **CGULL-030 (command injection):** propagate shell-command provenance through
   helper functions and modeled sanitizers.
4. **CGULL-044 (memory-copy overflow):** carry destination extent and size
   constraints across wrapper functions.
5. **Memory lifecycle rules:** extend CGULL-003 (unchecked allocation),
   CGULL-004 (parameter null checks), CGULL-021/023 (uninitialized values),
   CGULL-022 (use after free), CGULL-027 (double free), and CGULL-036 (leaks)
   with return, output-parameter, ownership, escape, and free effects. These
   rules already use the CFG and limited summaries, so they are good validation
   consumers after the shared model stabilizes.

CGULL-032 (realloc overwrite), CGULL-034 (division by zero), and CGULL-038
(returning stack storage) can follow where wrapper/return relationships provide
clear value. Pure style or syntactic-ban rules should not be made dependent on
taint merely because the infrastructure exists.

## Milestone work packages

### 1. Semantics and fixtures

- Specify lattices, joins, unknown behavior, alias limits, and rule-facing
  queries.
- Add small C fixtures for source/callee/sink combinations, wrappers, multiple
  callers, recursion, globals, aliases, and unresolved calls.
- Record current Juliet GoodSource/BadSink and BadSource/GoodSink results as a
  baseline, but require non-Juliet regression cases as acceptance tests.

### 2. TU call graph and shared session

- Emit direct call events and build the per-TU call graph.
- Introduce a shared analysis session in the scan pipeline, computed once per
  configuration profile.
- Preserve original-file/line provenance for functions expanded from headers.
- Keep file mode working; its analysis universe is simply the parsed file plus
  whatever content it currently expands. Document that full intra-TU results
  require TU mode.

### 3. Generalized summaries

- Replace the narrow summary loop with SCC-based fixed-point computation.
- Implement argument/formal, return/result, global, and side-effect transfer.
- Add standard-library models and a conservative unknown-call transfer.
- Migrate existing nullness/allocation/free behavior without regressions.

### 4. Taint and string consumers

- Migrate CGULL-002 first, then the data-dependent portions of CGULL-001 and
  CGULL-030.
- Report source-to-sink explanations when provenance is available.
- Retain syntactic fallback behavior when parsing or semantic resolution fails;
  do not claim a clean result from degraded analysis.

### 5. Memory and bounds consumers

- Migrate CGULL-044 and the prioritized memory lifecycle rules.
- Add ownership/escape and size-relationship summaries only as required by
  concrete rule queries, while keeping them in the shared domain.

### 6. Hardening and release gate

- Benchmark time and peak memory on representative projects and macro-heavy
  TUs; enforce configurable convergence/provenance limits with diagnostics.
- Compare file and TU modes, sequential and parallel scans, and configuration
  profiles for deterministic findings.
- Update rule metadata, Known Limitations, and release notes only after the
  relevant consumer ships.

Each work package may span multiple PRs, but PRs should land vertical,
test-backed slices behind an internal/experimental boundary until their package
acceptance criteria are met.

## Acceptance criteria

The milestone is complete when:

- direct calls within one expanded TU propagate parameter, return, and modeled
  side-effect facts through arbitrary wrapper depth and recursive SCCs;
- CGULL-002, the explicitly data-dependent CGULL-001 cases, and at least one
  memory/bounds rule consume the shared query API;
- GoodSource/BadSink and BadSource/GoodSink fixtures are distinguished when the
  distinction is semantically relevant, without suppressing unconditional API
  bans;
- unresolved calls and parse fallback produce conservative, explainable,
  deterministic results;
- existing function-summary and rule suites have no unintended regressions;
  and
- performance budgets and analysis limits are measured and documented.

## Deferred scope

Cross-TU project analysis is explicitly deferred. It requires stable symbol
identity for external/static linkage, duplicate-definition handling, build
configuration and compile-command awareness, whole-project invalidation/cache
keys, and coordination across parallel TU workers. Also deferred are full
points-to analysis, path-sensitive symbolic execution, concurrency, dynamic
dispatch through arbitrary function pointers, and proof of absence of a
vulnerability.

The next design should layer cross-TU summary import/export on this summary
format rather than merge per-TU CFGs into a whole-program supergraph.
