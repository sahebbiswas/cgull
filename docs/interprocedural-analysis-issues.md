---
repo: sahebbiswas/cgull
---

## Specify the interprocedural fact and query contract
Labels: enhancement, security, priority-p1

Define the finite abstract domains and the rule-facing API before expanding the
existing function summaries. This issue converts the milestone design into an
implementable semantic contract and prevents individual rules from inventing
incompatible notions of safe, tainted, or unknown.

### Scope

- Specify lattice values and joins for provenance, format literalness,
  nullness, initialization, allocation/ownership, buffer extent, and certainty.
- Define stable symbolic locations for locals, parameters, globals, named
  struct members, and index-insensitive arrays.
- Define transfer behavior for assignments, aliases, actual/formal binding,
  returns, output parameters, and unknown calls.
- Define a small rule-neutral query API, including the evidence and certainty
  returned with each answer.
- Record conservative behavior for unsupported expressions, pointer arithmetic,
  casts, unions, variadic forwarding, callbacks, and function pointers.

### Acceptance criteria

- The design document contains a truth table or equivalent executable-level
  specification for every join operation.
- Every query has documented inputs, outputs, and `unknown` behavior.
- At least one worked example covers each of parameter flow, return flow,
  side effects, recursion, and an unresolved call.
- The contract explicitly states that `unknown` is never treated as safe.

### Independence and value

This is documentation-only and can land without runtime changes. It gives all
subsequent implementation issues a stable compatibility target.

The resulting normative specification is maintained in
[interprocedural-fact-query-contract.md](interprocedural-fact-query-contract.md).

## Add an interprocedural regression corpus and baseline metrics
Labels: enhancement, security, priority-p1

Create focused fixtures and a repeatable metrics report before changing rule
behavior. The corpus should measure semantic improvements rather than rely only
on Juliet function names or benchmark labels.

### Scope

- Add fixtures for direct wrappers, multiple callers, return propagation,
  output parameters, globals, aliases, header-defined helpers, recursion, and
  unresolved calls.
- Cover safe and unsafe source/sink combinations for format strings, command
  execution, memory copy bounds, and allocation lifecycle.
- Record current findings for relevant Juliet GoodSource/BadSink and
  BadSource/GoodSink variants.
- Add a script or test helper that reports expected true positives, expected
  negatives, false positives, and false negatives by rule and fixture family.

### Acceptance criteria

- The corpus contains at least 20 small cases and at least one safe/unsafe pair
  for every scenario listed above.
- A single documented command produces deterministic baseline counts.
- CI asserts the fixture expectations without requiring the future analyzer to
  pass cases currently marked as known gaps.
- Each known-gap expectation links back to the interprocedural milestone.

### Independence and value

This can land in parallel with the semantic contract and immediately makes
progress measurable. It has no production-code dependency.

## Emit explicit call events from CFG construction
Labels: enhancement, tech-debt, priority-p1

Represent calls as first-class CFG data instead of repeatedly rediscovering
them from expression strings. This is the smallest production slice needed by
the call graph and summary transfer work.

### Scope

- Extend `CFGEvent` with direct callee identity, ordered actual argument
  expressions, optional result target, and source location.
- Emit call metadata for standalone calls, assignment/declaration initializers,
  return expressions, and nested value-producing calls supported by the parser.
- Preserve all existing reads, writes, allocation, and free event behavior.
- Mark indirect or unresolved callees explicitly rather than dropping them.

### Acceptance criteria

- Unit tests cover each supported call shape and assert argument order and
  result binding.
- Calls originating in expanded headers retain correct line-map provenance.
- Indirect calls produce an unresolved call event.
- The existing CFG and rule test suites pass unchanged.

### Dependencies

Uses the symbolic-location decisions from **Specify the interprocedural fact and
query contract** where available; the event metadata itself can land first if
it remains representation-only.

## Build a deterministic direct-call graph per translation unit
Labels: enhancement, security, priority-p1

Build a reusable call graph from explicit CFG call events for all function
definitions visible in one expanded translation unit.

### Scope

- Resolve direct calls to definitions in the current expanded TU.
- Record external/unresolved call edges separately.
- Compute strongly connected components and a deterministic bottom-up
  processing order.
- Preserve linkage and source provenance needed to distinguish static helpers
  and header-defined functions within the TU.
- Expose callers, callees, SCC membership, and unresolved edges through a small
  API.

### Acceptance criteria

- Tests cover an acyclic graph, mutual recursion, self-recursion, a
  header-defined helper, a static function, and an unresolved external call.
- Graph and SCC order are stable across repeated runs.
- No edge crosses translation units or guesses a target for an indirect call.
- Graph construction time is reported for a synthetic TU with at least 1,000
  functions.

### Dependencies

Depends on **Emit explicit call events from CFG construction**.

## Introduce one shared analysis session per TU and configuration profile
Labels: enhancement, tech-debt, priority-p1

Create a per-TU analysis session owned by the scan pipeline so call graphs,
summaries, and queries are computed once and shared consistently by all rules.

### Scope

- Add an analysis-session object containing the AST context, call graph,
  function summaries, configuration identity, and query interface.
- Make the session available to AST rules without breaking existing custom
  `BaseRule.scan_ast` implementations.
- Lazily compute expensive domains so regex-only scans do not pay the cost.
- Define session lifetime separately for each preprocessor configuration
  profile.
- Instrument summary construction count for tests.

### Acceptance criteria

- Two rules requesting summaries during one TU/profile scan observe the same
  session and trigger one summary computation.
- Different configuration profiles never share analysis state.
- Sequential and parallel scan results remain identical.
- Existing third-party/custom rule method signatures remain supported.

### Dependencies

Depends on **Build a deterministic direct-call graph per translation unit**.

## Replace ad hoc summary iteration with an SCC fixed-point engine
Labels: enhancement, security, priority-p1

Generalize the current `analyze_function_summaries` loop into a terminating,
deterministic engine that can host multiple fact domains while preserving the
existing memory semantics.

### Scope

- Process call-graph SCCs bottom-up and iterate recursive SCCs until stable.
- Require finite lattices and monotone transfer functions.
- Add configurable iteration/provenance bounds and surface convergence
  diagnostics rather than silently accepting partial state.
- Port `freed_params`, return nullness, and allocation-return facts to the new
  engine.
- Keep a compatibility wrapper for current callers during migration.

### Acceptance criteria

- Existing nullness/allocation/free summary tests produce equivalent results.
- Tests demonstrate convergence for self-recursion and mutual recursion.
- Summary output is byte-for-byte deterministic after canonical serialization.
- A forced limit produces conservative unknown facts and a visible diagnostic.
- No rule behavior changes solely from enabling the new engine.

### Dependencies

Depends on **Introduce one shared analysis session per TU and configuration
profile** and the lattice contract in **Specify the interprocedural fact and
query contract**.

## Add declarative models and conservative unknown-call effects
Labels: enhancement, security, priority-p1

Move standard C/POSIX call knowledge into validated declarative models and make
unmodeled calls conservatively affect analysis state.

### Scope

- Model source, sink, sanitizer, format-position, allocation, deallocation,
  output-parameter, and size-relationship effects.
- Seed models for the standard functions already hard-coded by existing rules
  and summaries.
- Validate function names, argument positions, and contradictory effects at
  load time.
- Define merge/override behavior for project configuration.
- Apply an explicit unknown-call transfer when resolution or modeling fails.

### Acceptance criteria

- Existing built-in allocation/deallocation behavior is represented by models
  with no rule regressions.
- Tests reject malformed and contradictory models with actionable errors.
- An absent model cannot erase taint, prove initialization, or prove memory
  safety.
- A project-defined wrapper model changes analysis results in an end-to-end
  fixture without code changes.

### Dependencies

Depends on **Replace ad hoc summary iteration with an SCC fixed-point engine**.
The model parser and validation can be developed independently before engine
integration.

## Propagate provenance and format-literal facts through calls
Labels: enhancement, security, priority-p1

Implement the first new summary domain: value provenance and string-format
literalness across parameters, returns, assignments, aliases, and modeled
calls.

### Scope

- Track trusted constants, external/untrusted values, mixed values, and unknown.
- Track whether a string value is a proven literal, proven non-literal, or
  unknown.
- Propagate actual arguments to formals and callee return relationships to
  caller result variables.
- Merge facts conservatively for multiple callers and recursive SCCs.
- Retain bounded source-to-value evidence for rule explanations.

### Acceptance criteria

- Safe and unsafe facts propagate through at least three wrapper levels.
- Multiple safe and unsafe callers produce a conservative merged summary.
- Return-of-parameter and return-of-literal cases are distinguished.
- Recursive and unresolved-call fixtures converge to documented results.
- Evidence size remains within the configured bound.

### Dependencies

Depends on **Replace ad hoc summary iteration with an SCC fixed-point engine**;
modeled source/sanitizer behavior depends on **Add declarative models and
conservative unknown-call effects**.

## Migrate CGULL-002 format-string analysis to interprocedural facts
Labels: enhancement, security, priority-p1

Make CGULL-002 the first end-to-end rule consumer. Preserve syntactic fallback
when semantic analysis is unavailable while distinguishing proven literal
formats from caller-controlled formats across helper functions.

### Scope

- Query format literalness and provenance at `printf`-family and `syslog`
  sinks, including modeled wrappers.
- Preserve findings for unknown or parser-fallback cases with limited
  confidence rather than treating them as safe.
- Include a compact source-to-sink explanation when evidence is available.
- Keep current safe-fix generation limited to transformations already known to
  be mechanically safe.

### Acceptance criteria

- The interprocedural CGULL-002 corpus has no false negatives for unsafe cases.
- Proven literal formats passed through helpers do not produce findings.
- Untrusted formats passed through at least three functions do produce findings
  at the sink with source and sink locations.
- File mode, TU mode, parse fallback, and unresolved-call behaviors are covered.
- Existing CGULL-002 tests pass or have reviewed expectation changes.

### Dependencies

Depends on **Propagate provenance and format-literal facts through calls** and
**Introduce one shared analysis session per TU and configuration profile**.

## Separate unconditional and data-dependent CGULL-001 policy
Labels: enhancement, security, priority-p1

Make the policy boundary in CGULL-001 explicit before using dataflow to refine
findings. An intrinsically banned or user-configured API must not become safe
because its source is trusted.

### Scope

- Classify built-in banned functions as unconditional bans or data-dependent
  sink checks, with a documented reason for every entry.
- Preserve unconditional reports for `gets`, insecure temporary-file APIs,
  intrinsically unbounded APIs, and project-configured bans unless configuration
  explicitly says otherwise.
- Allow provenance, destination capacity, and source extent to refine only the
  data-dependent classifications.
- Expose the classification and semantic evidence in finding messages/metadata.

### Acceptance criteria

- A trusted source does not suppress an unconditional `strcpy` or `gets`
  finding.
- At least one data-dependent fixture demonstrates a justified precision
  improvement across a helper boundary.
- Every default banned function has a table-driven policy test.
- Juliet expectation changes are justified by semantics, not Good/Bad names.
- Regex/parser fallback retains conservative existing coverage.

### Dependencies

Policy classification can land independently. Semantic refinement depends on
**Propagate provenance and format-literal facts through calls** and the later
buffer-extent domain where capacity is relevant.

## Migrate CGULL-030 command-injection analysis to interprocedural facts
Labels: enhancement, security, priority-p2

Track command provenance through helper functions so CGULL-030 reports modeled
untrusted input reaching command-execution sinks and recognizes only explicitly
modeled sanitization.

### Scope

- Identify command sources, execution sinks, and sanitizers through declarative
  models.
- Propagate command strings through parameters, returns, assignments, and
  wrappers.
- Preserve conservative behavior for concatenation, partial sanitization,
  unresolved calls, and parse fallback.
- Attach bounded source-to-sink evidence to findings.

### Acceptance criteria

- Unsafe input crossing at least three helper functions is reported.
- A constant command and an explicitly modeled complete sanitizer produce the
  documented safe result.
- Concatenating any untrusted component remains untrusted.
- Unknown calls do not launder an untrusted command.
- Existing CGULL-030 tests and the new regression corpus pass.

### Dependencies

Depends on **Propagate provenance and format-literal facts through calls** and
**Add declarative models and conservative unknown-call effects**. It is
independent of CGULL-001 and CGULL-002 migrations.

## Propagate buffer extents and size constraints through calls
Labels: enhancement, security, priority-p2

Add a bounded size domain capable of carrying known destination capacity and
size relationships through wrappers without attempting general symbolic
execution.

### Scope

- Represent exact constant extents, conservative lower/upper bounds, parameter
  relationships, and unknown.
- Propagate array/struct-member extents through actual/formal binding and simple
  aliases.
- Summarize constraints such as `size <= capacity` proven by existing CFG edge
  facts.
- Remain field-sensitive for named members and index-insensitive for arrays.
- Treat pointer arithmetic and unsupported arithmetic conservatively.

### Acceptance criteria

- Known array and named struct-member capacities survive at least two wrapper
  calls.
- Safe and unsafe constant sizes are distinguished.
- A branch guard recognized by the existing CFG refines only the guarded path.
- Unknown arithmetic never produces a proof of safety.
- Join and convergence tests cover conflicting callers and recursion.

### Dependencies

Depends on **Replace ad hoc summary iteration with an SCC fixed-point engine**
and **Emit explicit call events from CFG construction**. It can proceed in
parallel with provenance-rule migrations.

## Migrate CGULL-044 memory-copy bounds analysis to interprocedural facts
Labels: enhancement, security, priority-p2

Use propagated destination extents and size constraints to detect unsafe
`memcpy`, `memmove`, and `memset` calls inside wrappers.

### Scope

- Query destination capacity and requested size at direct and modeled wrapper
  sinks.
- Report proven overflow, preserve conservative review for unknown bounds, and
  suppress only when safety is proven under the rule's policy.
- Preserve named struct-member and plain-array behavior already covered by
  CGULL-044.
- Include caller/callee evidence for interprocedural findings.

### Acceptance criteria

- Proven overflow across at least two helper functions is reported at the
  actionable sink/call location.
- A proven in-bounds copy across a wrapper does not produce a finding.
- Conflicting caller sizes merge conservatively without missing the unsafe call.
- Header-defined wrappers retain correct source provenance.
- Existing CGULL-044 tests pass without lost coverage.

### Dependencies

Depends on **Propagate buffer extents and size constraints through calls** and
**Introduce one shared analysis session per TU and configuration profile**.

## Propagate initialization, nullness, and output-parameter effects
Labels: enhancement, security, priority-p2

Extend summaries for functions that initialize or validate caller-owned values,
including output parameters. This delivers precision improvements for existing
CFG rules without requiring the ownership domain.

### Scope

- Summarize must/may writes and initialization of pointer-referenced output
  parameters.
- Propagate nullness through parameter checks, return values, and modeled
  functions.
- Migrate CGULL-003, CGULL-004, CGULL-021, and CGULL-023 to shared queries where
  interprocedural facts are relevant.
- Preserve conservative results for alias ambiguity and unknown calls.

### Acceptance criteria

- A helper that definitely initializes an output parameter prevents the
  corresponding false positive.
- Conditional initialization remains maybe-initialized and is not treated as
  safe.
- Caller-side null checks and callee-return nullness propagate through wrappers.
- Each migrated rule has at least one independently valuable safe/unsafe pair.
- Existing rule suites pass with reviewed expectation changes.

### Dependencies

Depends on **Replace ad hoc summary iteration with an SCC fixed-point engine**
and **Add declarative models and conservative unknown-call effects**. It can be
implemented independently of taint and bounds domains.

## Propagate allocation ownership, escape, and free effects
Labels: enhancement, security, priority-p2

Generalize the existing `freed_params` and allocation-return summaries into an
ownership/effect domain for CGULL-022, CGULL-027, and CGULL-036.

### Scope

- Track newly allocated returns, frees, possible frees, ownership transfer,
  global/unknown escape, and returned aliases.
- Apply callee effects to caller symbolic locations, including simple aliases.
- Migrate use-after-free, double-free, and leak rules to shared effect queries.
- Keep unresolved calls conservative without assuming every call frees every
  pointer.

### Acceptance criteria

- Free-in-callee followed by caller use is reported.
- Free-in-callee followed by caller free is reported as a double free.
- Allocation returned through wrappers is tracked to a caller free or exit.
- A modeled ownership transfer prevents a false leak while an unknown escape
  produces the documented conservative result.
- Existing CGULL-022, CGULL-027, and CGULL-036 tests pass.

### Dependencies

Depends on **Replace ad hoc summary iteration with an SCC fixed-point engine**
and **Add declarative models and conservative unknown-call effects**. It can be
implemented independently of provenance, format strings, and bounds.

## Add interprocedural evidence and degraded-analysis diagnostics
Labels: enhancement, security, priority-p2

Make interprocedural findings explainable and ensure analysis limits or parser
degradation never look like a proof of safety.

### Scope

- Define compact evidence steps for source, assignment, argument/formal,
  return/result, modeled effect, and sink.
- Render source and sink locations in human-readable and SARIF output without
  breaking existing consumers.
- Surface unresolved-call, convergence-limit, provenance-limit, and parser
  fallback reasons.
- Bound and deterministically truncate evidence paths.

### Acceptance criteria

- An interprocedural finding identifies source, sink, and intervening function
  names when known.
- SARIF output validates against the repository schema.
- Truncated evidence is marked as truncated and remains deterministic.
- A degraded analysis cannot emit metadata claiming a value is proven safe.
- Existing output snapshots remain compatible or have documented versioned
  changes.

### Dependencies

The evidence data model depends on **Specify the interprocedural fact and query
contract**. Rendering can land before individual rule migrations; end-to-end
tests should use CGULL-002 once migrated.

## Establish performance, determinism, and release gates
Labels: enhancement, tech-debt, priority-p2

Define measurable release gates for the intra-TU milestone and update public
documentation only when shipped behavior satisfies them.

### Scope

- Benchmark wall time and peak memory for representative projects, a
  macro-heavy TU, deep wrappers, and large recursive SCCs.
- Test determinism across repeated runs, file/TU modes, configuration profiles,
  and sequential/parallel scanning.
- Set documented budgets for summary iterations, provenance size, runtime
  overhead, and memory overhead.
- Report regression-corpus precision/recall deltas by migrated rule.
- Update rule metadata, Known Limitations, and release notes to describe actual
  shipped coverage and deferred cross-TU scope.

### Acceptance criteria

- CI or a documented release command produces a machine-readable benchmark and
  regression report.
- Repeated and parallel runs produce identical normalized findings.
- No configured analysis limit fails silently.
- CGULL-002, data-dependent CGULL-001 behavior, and at least one memory/bounds
  rule meet their corpus acceptance criteria.
- Cross-TU analysis, full points-to analysis, symbolic execution, concurrency,
  and arbitrary function pointers remain explicitly documented as deferred.

### Dependencies

Benchmark scaffolding can land early. Final release gating depends on the rule
migration issues selected for the milestone acceptance criteria.
