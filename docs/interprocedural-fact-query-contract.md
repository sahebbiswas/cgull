# Interprocedural Fact and Query Contract

## Status

This document is the normative semantic contract for the first intra-translation
unit (TU) interprocedural analysis milestone. It specifies the compatibility
target for the future summary engine and rule-facing API; it does not describe
runtime behavior that has already shipped.

The current `cgull.cfg` implementation uses variable-name keyed facts and the
narrow `FunctionSummary` fields `freed_params`, `unsafe_deref_params`,
`return_nullness`, and `returns_allocation`. The implementation may migrate
those fields incrementally, but new summary domains and rule consumers must
follow this contract. Rule policy remains outside the analysis package.

## Normative invariants

The words **must**, **must not**, **should**, and **may** are normative.

1. Every domain has an internal bottom value, written `BOTTOM`, which means
   "no reachable path has contributed a fact yet". Queries never return
   `BOTTOM`.
2. Every domain has an `UNKNOWN` value or encoding, which means analysis could
   not determine the value conservatively. `UNKNOWN` is the lattice top and
   dominates joins. It is distinct from `BOTTOM`.
3. **`UNKNOWN` is never treated as safe.** A rule may retain its existing
   syntactic finding, lower confidence, or request review, but it must not
   suppress a finding because a semantic query returned `UNKNOWN`.
4. Joins are commutative, associative, and idempotent. Transfer functions are
   monotone. These properties are required for deterministic SCC fixed-point
   computation.
5. Facts describe all reachable executions represented by the CFG. A single
   known value is a proof only when its answer is complete and its certainty
   permits the rule's decision.
6. Analysis limits, unsupported syntax, unresolved calls, and parse fallback
   degrade affected facts to `UNKNOWN` and add an explicit diagnostic. They
   never produce a clean bill of health.

## Common representation

### Program points

A `ProgramPoint` is `(function_symbol, event_id, phase)`, where `phase` is
`BEFORE` or `AFTER`. `event_id` is the deterministic CFG event ordinal within
the function. Arguments are queried at `BEFORE` a call; call results and
effects are queried at `AFTER` it.

### Symbolic locations

Facts attach to symbolic storage locations rather than source spellings:

| Source entity | Symbolic root |
| --- | --- |
| Parameter | `Param(function_symbol, parameter_index)` |
| Local | `Local(function_symbol, declaration_ordinal)` |
| External-linkage global | `Global(EXTERNAL, name)` |
| Internal-linkage global | `Global(INTERNAL, tu_key, name)` |
| Allocation site | `AllocationSite(function_symbol, event_id)` |
| Unresolved storage | `UnknownLocation` |

`function_symbol` contains the function name, linkage, TU key for internal
linkage, and canonical definition source anchor. `declaration_ordinal` is the
lexical declaration order in the function after preprocessing, with the
original source anchor retained for evidence. These identities distinguish
shadowed locals and same-named static helpers while remaining deterministic
for a fixed expanded TU and configuration profile.

Locations may have projections:

- `Member(base, field_name)` for a named `struct` member. Nested named members
  compose, for example `Member(Member(x, "header"), "length")`.
- `Elements(base)` for every element of an array. Version one is deliberately
  index-insensitive: `a[0]`, `a[i]`, and `a[7]` resolve to the same projection.
- `Pointee(base, depth)` only in summaries and effect targets. At a call site it
  is substituted with the actual argument's points-to set.

Union members do not get independent locations. Access to a union or a field
reached through an unknown projection resolves to `UnknownLocation`.

The points-to domain is the powerset of the finite locations created for the
expanded TU plus `UnknownLocation`. Its join is set union:

```text
join_locations(left, right) = left union right
```

The empty set is `BOTTOM`. A set containing `UnknownLocation` is unknown even
if it also contains known locations. Implementations must cap the set size;
exceeding the configured cap replaces it with `{UnknownLocation}` and records
`ALIAS_LIMIT`.

Return and value-dependency relationships use the same finite-set shape:

```text
RelationAtom = Parameter(i) | Global(location) | FreshAllocation(site) |
               Constant(value) | UnknownRelation
RelationFact = subset(RelationAtom)
BOTTOM       = empty set
join(left, right) = left union right
```

A set containing `UnknownRelation` is unknown. Constants and relationship
atoms come only from the finite TU/model universe. Exceeding the relationship
cap produces `{UnknownRelation}` and `EVIDENCE_LIMIT`.

### Value and referent subjects

Queries distinguish the value stored in a location from an object reached by a
pointer:

- `Value(location_or_expression)` asks about the scalar or pointer value.
- `Referent(pointer_expression, depth=1)` asks about the pointee object. String
  provenance, object initialization, and buffer extent normally use this form.

For example, assigning `q = p` changes `Local(q)` and copies the pointer value
and points-to set; it does not merge `Local(q)` with `Local(p)`. Both pointer
values may subsequently refer to the same allocation location.

## Abstract domains and joins

Tables use `B` for `BOTTOM`, `T` for `TRUSTED`, `U` for `UNTRUSTED`, `M` for a
known mixed or path-dependent state, and `?` for `UNKNOWN` where appropriate.

### Provenance

`TRUSTED` means the value is proven to originate only from trusted constants or
a modeled sanitizer. Evidence records which one. `UNTRUSTED` means at least one
modeled external source reaches the value. `MIXED` means both trusted and
untrusted contributions are known. `UNKNOWN` means some contribution cannot be
classified.

| `join` | `B` | `TRUSTED` | `UNTRUSTED` | `MIXED` | `UNKNOWN` |
| --- | --- | --- | --- | --- | --- |
| `B` | `B` | `TRUSTED` | `UNTRUSTED` | `MIXED` | `UNKNOWN` |
| `TRUSTED` | `TRUSTED` | `TRUSTED` | `MIXED` | `MIXED` | `UNKNOWN` |
| `UNTRUSTED` | `UNTRUSTED` | `MIXED` | `UNTRUSTED` | `MIXED` | `UNKNOWN` |
| `MIXED` | `MIXED` | `MIXED` | `MIXED` | `MIXED` | `UNKNOWN` |
| `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` |

`MIXED` is not safe: it contains a known untrusted contribution. A modeled
sanitizer may produce `TRUSTED`, with sanitizer evidence, only when its model's
preconditions are satisfied.

### Format literalness

This domain describes the bytes consumed as a format string, not whether the
pointer expression itself is a literal.

| `join` | `BOTTOM` | `LITERAL` | `NON_LITERAL` | `UNKNOWN` |
| --- | --- | --- | --- | --- |
| `BOTTOM` | `BOTTOM` | `LITERAL` | `NON_LITERAL` | `UNKNOWN` |
| `LITERAL` | `LITERAL` | `LITERAL` | `UNKNOWN` | `UNKNOWN` |
| `NON_LITERAL` | `NON_LITERAL` | `UNKNOWN` | `NON_LITERAL` | `UNKNOWN` |
| `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` |

Adjacent C string literals folded by the parser are `LITERAL`. A local array
initialized from a literal may retain `LITERAL` until a possible write to its
bytes. Runtime concatenation is `NON_LITERAL`; an unresolved possible write is
`UNKNOWN`.

### Nullness

`MAYBE_NULL` is a known path union of null and non-null alternatives.
`UNKNOWN` means the analysis lacks even that complete classification.

| `join` | `BOTTOM` | `NULL` | `NON_NULL` | `MAYBE_NULL` | `UNKNOWN` |
| --- | --- | --- | --- | --- | --- |
| `BOTTOM` | `BOTTOM` | `NULL` | `NON_NULL` | `MAYBE_NULL` | `UNKNOWN` |
| `NULL` | `NULL` | `NULL` | `MAYBE_NULL` | `MAYBE_NULL` | `UNKNOWN` |
| `NON_NULL` | `NON_NULL` | `MAYBE_NULL` | `NON_NULL` | `MAYBE_NULL` | `UNKNOWN` |
| `MAYBE_NULL` | `MAYBE_NULL` | `MAYBE_NULL` | `MAYBE_NULL` | `MAYBE_NULL` | `UNKNOWN` |
| `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` |

Branch predicates may refine a fact on an edge, such as `p != NULL` producing
`NON_NULL` on the true edge. An unsupported predicate leaves the fact
unchanged; it does not manufacture `NON_NULL`.

### Initialization

Initialization is tracked per symbolic location or index-insensitive aggregate
projection.

| `join` | `BOTTOM` | `UNINITIALIZED` | `INITIALIZED` | `MAYBE_INITIALIZED` | `UNKNOWN` |
| --- | --- | --- | --- | --- | --- |
| `BOTTOM` | `BOTTOM` | `UNINITIALIZED` | `INITIALIZED` | `MAYBE_INITIALIZED` | `UNKNOWN` |
| `UNINITIALIZED` | `UNINITIALIZED` | `UNINITIALIZED` | `MAYBE_INITIALIZED` | `MAYBE_INITIALIZED` | `UNKNOWN` |
| `INITIALIZED` | `INITIALIZED` | `MAYBE_INITIALIZED` | `INITIALIZED` | `MAYBE_INITIALIZED` | `UNKNOWN` |
| `MAYBE_INITIALIZED` | `MAYBE_INITIALIZED` | `MAYBE_INITIALIZED` | `MAYBE_INITIALIZED` | `MAYBE_INITIALIZED` | `UNKNOWN` |
| `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` |

An output-parameter model may establish `INITIALIZED`. Merely passing a
location to an unresolved call produces `UNKNOWN`, not `INITIALIZED`.

### Allocation and ownership

Allocation and ownership are finite powerset domains. This avoids an ambiguous
collection of `MAYBE_*` enum values and gives an executable specification for
every join.

```text
AllocationAtom = {NOT_ALLOCATED, LIVE, FREED}
OwnershipAtom  = {NONE, OWNED, BORROWED, ESCAPED}

AllocationFact = subset(AllocationAtom)
OwnershipFact  = subset(OwnershipAtom)

BOTTOM  = empty set
UNKNOWN = full atom set
join(left, right) = left union right
```

Examples:

| Meaning | Allocation fact | Ownership fact |
| --- | --- | --- |
| Definite live allocation owned here | `{LIVE}` | `{OWNED}` |
| Allocation may have failed | `{NOT_ALLOCATED, LIVE}` | `{NONE, OWNED}` |
| May have been freed | `{LIVE, FREED}` | unchanged or `{OWNED, ESCAPED}` |
| Definite free | `{FREED}` | `{NONE}` |
| Unresolved ownership | `{NOT_ALLOCATED, LIVE, FREED}` | `{NONE, OWNED, BORROWED, ESCAPED}` |

Allocation facts attach to allocation identities; pointer values carry a
points-to set. Multiple aliases do not imply multiple owners. `ESCAPED` means
the allocation may be retained, freed, or transferred outside the analyzer's
known ownership boundary. It is never evidence that a leak or use is safe.

### Buffer extent

Extent is measured in bytes. To keep the domain finite, an analysis session
builds finite sets `K` of folded non-negative constants and `D` of parameter
offsets appearing in the TU or validated models. It supports:

```text
BOTTOM
Bounds(lower, upper)                 lower in K, upper in K or INFINITY
ParamBounds(parameter, low_delta, high_delta)
UNKNOWN                              lattice top
```

`Bounds(n, n)` is an exact extent. `ParamBounds(0, 0, 0)` means the extent is
exactly parameter 0. Results whose constants or offsets are outside `K` or `D`
normalize to `UNKNOWN` rather than extending the lattice during iteration.

The complete join algorithm is:

```text
join_extent(BOTTOM, x) = x
join_extent(x, BOTTOM) = x
join_extent(UNKNOWN, x) = UNKNOWN
join_extent(x, UNKNOWN) = UNKNOWN

join_extent(Bounds(l1, u1), Bounds(l2, u2)) =
    Bounds(min(l1, l2), max(u1, u2))

join_extent(ParamBounds(p, l1, u1), ParamBounds(p, l2, u2)) =
    ParamBounds(p, min(l1, l2), max(u1, u2))

join_extent(any other pair) = UNKNOWN
```

The result is a hull over paths: its lower bound is guaranteed and its upper
bound is possible. Rules comparing a requested byte count with capacity must
use the lower bound to prove safety and the upper bound to prove overflow. All
other comparisons are unknown/review cases.

### Certainty

Certainty qualifies an effect or relationship, not the safety policy. `MUST`
means it occurs on every represented path, `MAY` means it occurs on at least one
known path, and `UNKNOWN` means incomplete analysis prevents classification.

| `join` | `BOTTOM` | `MUST` | `MAY` | `UNKNOWN` |
| --- | --- | --- | --- | --- |
| `BOTTOM` | `BOTTOM` | `MUST` | `MAY` | `UNKNOWN` |
| `MUST` | `MUST` | `MUST` | `MAY` | `UNKNOWN` |
| `MAY` | `MAY` | `MAY` | `MAY` | `UNKNOWN` |
| `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` |

Absence of an effect is represented by no effect record only when the enclosing
summary is complete. In an incomplete summary, a missing effect is
`UNKNOWN`, not proof that the effect never occurs.

Effect maps are joined by target and effect kind. This is the complete merge
rule around the certainty table:

```text
join_effect(left, right):
    present in both complete branches -> join values; join certainties
    present in only one complete branch -> retain value; certainty = MAY
    present in either branch and the other branch is incomplete -> UNKNOWN
    absent in both complete branches -> no effect record
    absent in either incomplete branch -> UNKNOWN when queried
```

### Product facts

`ValueFacts` is the product of provenance, format literalness, nullness,
initialization, allocation, ownership, and extent. Its join applies the join
defined above to each component. A component may be inapplicable to a C type;
an inapplicable component is omitted, not reported as safe. A requested omitted
component is returned as `UNKNOWN`.

## Evidence and degradation

Every non-bottom fact carries bounded evidence. An `EvidenceRef` contains:

- a stable kind: `SOURCE`, `ASSIGNMENT`, `BRANCH`, `CALL`, `RETURN`, `MODEL`,
  `SIDE_EFFECT`, `JOIN`, or `DEGRADATION`;
- the original source location when available;
- the function/call/model identity; and
- zero or more predecessor evidence IDs.

Evidence is a DAG, not a serialized CFG path. Joining evidence takes the union,
sorts by `(source_path, line, column, kind, identity)`, removes duplicates, and
retains the first configured `N` nodes after preserving the nearest source,
sink, and degradation nodes. Truncation adds `EVIDENCE_LIMIT`; it does not
change a sound fact, but the answer reports that its explanation is incomplete.

`Degradation` is one of `UNRESOLVED_CALL`, `INDIRECT_CALL`,
`UNSUPPORTED_EXPRESSION`, `UNSUPPORTED_CAST`, `UNION_ACCESS`,
`VARIADIC_FORWARDING`, `CALLBACK`, `ALIAS_LIMIT`, `EVIDENCE_LIMIT`,
`CONVERGENCE_LIMIT`, or `PARSER_FALLBACK`. The list may grow compatibly;
consumers must not treat an unrecognized degradation as safe.

## Transfer contract

### Declarations, constants, and assignments

- An uninitialized local starts `UNINITIALIZED`. Parameters and initialized
  globals start `INITIALIZED`; their other domains depend on caller input,
  initializer evaluation, or linkage visibility.
- Integer/character constants and string literal bytes are `TRUSTED`. String
  literal referents are `LITERAL`, `INITIALIZED`, `NON_NULL`, and have exact
  byte extent including the terminating NUL.
- `x = y` copies the supported value facts of `Value(y)` to `Value(x)`. For
  pointer types it also copies the points-to set. It does not alias the storage
  locations of `x` and `y`.
- `p = &x` makes `Value(p)` point to the symbolic location of `x` and makes the
  pointer `NON_NULL`.
- `*p = y` is a strong update only when `p` has one known target and the edge
  proves that target is selected. With multiple possible targets it weakly
  joins `y` into every target. If the set contains `UnknownLocation`, all
  potentially affected externally visible storage is degraded to `UNKNOWN`.
- Named struct-member assignment updates only that member. Aggregate assignment
  copies each known named member. Array element writes update `Elements(base)`.
- Supported pure expression operators join operand provenance. Literalness is
  retained only for compile-time-folded string literals. Address-dependent
  facts use the unsupported-expression behavior below unless a transfer is
  explicitly defined.

### Actual/formal binding

At a resolved direct call, actual argument `i` is evaluated at the call's
`BEFORE` point and copied into `Param(callee, i)`. A pointer actual copies its
points-to set. Reassignment of the formal itself cannot modify the caller's
pointer variable; writes through the formal are represented as pointee effects.

Because the first milestone is context-insensitive, inputs from all call sites
join at each formal. Summaries express dependencies such as `Return <- Param(0)`
and `Pointee(Param(1)) <- Param(0)` so applying the summary substitutes facts
from the individual call site rather than replacing them with parameter names.

Argument evaluation order is not assumed beyond C's sequencing rules. If two
arguments have potentially conflicting unsequenced effects, affected facts are
`UNKNOWN` and carry `UNSUPPORTED_EXPRESSION`.

### Returns

Each return expression transfers its value facts and points-to relationship to
the synthetic `Return(function)` location. Multiple reachable returns join.
Summary relationships may be `Parameter(i)`, `Global(location)`,
`FreshAllocation(site)`, a known constant, or `UNKNOWN`.

At a call site the return relationship is substituted into the caller. A
returned alias preserves allocation identity and ownership; returning an
allocation does not invent a second allocation site. A missing return from a
non-`void` function, unsupported return expression, or unresolved callee yields
`UNKNOWN`.

### Output parameters and other side effects

A summary effect has `(target, kind, value, certainty, evidence)`, where target
is `Pointee(Param(i), depth)` or a global and kind is `WRITE`, `INITIALIZE`,
`FREE`, `ESCAPE`, or `OWNERSHIP_TRANSFER`.

At the caller, the target is substituted through the actual argument's
points-to set. Singleton targets permit strong updates; multiple targets use
weak joins. A `MUST` effect becomes `MAY` if substitution has multiple possible
targets. `FREE` adds `FREED` to or replaces the allocation fact according to
certainty. `ESCAPE` and ownership transfer add the corresponding ownership
alternatives; neither silently discharges a leak unless the rule's policy and
a complete model explicitly recognize the transfer.

Writes to external globals are summary effects. Internal globals are keyed by
the TU and cannot collide with same-named globals from another TU.

### Unknown calls

An unresolved direct call, indirect call, callback invocation, or call without
a validated model uses this transfer:

1. The return value is `UNKNOWN`; a pointer return points to
   `{UnknownLocation}`.
2. Scalar arguments passed by value remain unchanged in caller storage.
3. For a pointer passed by value, its pointer value remains unchanged, but each
   known pointee's content facts become `UNKNOWN`; a live allocation gains a
   possible `FREED` state and `ESCAPED` ownership.
4. For an address-of argument or pointer depth greater than one, the caller
   location may be rewritten: its facts become `UNKNOWN` and its points-to set
   gains `UnknownLocation`.
5. Externally visible globals, and internal globals whose addresses escaped,
   become `UNKNOWN`.
6. The call has incomplete side effects with `UNKNOWN` certainty and
   `UNRESOLVED_CALL` or `INDIRECT_CALL` evidence.

A `const` qualifier alone does not prove that an unknown callee will not retain
an address or cast away const. Only a validated function model may narrow this
transfer.

### Unsupported constructs

- Pointer arithmetic produces unknown points-to, extent, nullness, allocation,
  and ownership facts unless a validated model handles the exact operation.
- Qualifier-only and compatible pointer casts may preserve facts. Integer to
  pointer, pointer to integer, incompatible object pointer, and representation-
  changing casts yield `UNKNOWN` with `UNSUPPORTED_CAST`.
- A union write invalidates all overlapping storage; subsequent union reads are
  `UNKNOWN` unless a future domain explicitly models active members.
- Fixed parameters of a variadic function transfer normally. Variadic
  forwarding and `va_list` content are `UNKNOWN` unless modeled.
- Function-pointer calls and callbacks use the unknown-call transfer. The
  analyzer never guesses a target from matching signatures.
- Parser fallback has no semantic proof. All interprocedural queries for the
  affected function/TU return `UNKNOWN` with `PARSER_FALLBACK`.
- When an SCC exceeds its iteration budget, every fact that has not converged
  is raised to `UNKNOWN` with `CONVERGENCE_LIMIT`; the last partial value is not
  exposed as final.

## Rule-facing query API

The API is read-only and rule-neutral. It is owned by one analysis session per
expanded TU and configuration profile.

All methods return:

```text
FactAnswer[T] {
    value: T                 # never BOTTOM
    certainty: MUST | MAY | UNKNOWN
    evidence: tuple[EvidenceRef, ...]
    degradations: tuple[Degradation, ...]
    complete: bool
}
```

`complete` means no unknown contribution can affect this answer. It does not
mean the value is safe. Rules must check the domain value, certainty,
completeness, and their own policy.

For state queries, `MUST` means the returned abstract value covers every
represented path; it does not mean every concrete alternative inside a set or
interval occurs on every path. `MAY` is used for a weak/subset effect.

### `facts_at(point, subject) -> FactAnswer[ValueFacts]`

- **Inputs:** a valid `ProgramPoint` and `Value(...)` or `Referent(...)`
  subject.
- **Output:** the product facts immediately before or after the selected event.
- **Unknown behavior:** an invalid/unreachable point, unresolved expression,
  unavailable requested projection, or parser fallback returns all requested
  components as `UNKNOWN`, `certainty=UNKNOWN`, `complete=false`, and a
  degradation. It never falls back to `UNINITIALIZED`, `NOT_ALLOCATED`, or any
  other apparently safe default.

### `points_to(point, pointer) -> FactAnswer[frozenset[SymbolicLocation]]`

- **Inputs:** a point and pointer-valued location/expression.
- **Output:** all possible referent locations at the point.
- **Unknown behavior:** unsupported pointer production, an alias cap, or a
  non-pointer subject returns `{UnknownLocation}`, `certainty=UNKNOWN`, and
  `complete=false`. A set containing `UnknownLocation` must not authorize a
  strong update or a safety proof.

### `call_effect(call_point, target, kind) -> FactAnswer[Effect]`

- **Inputs:** the `BEFORE` or `AFTER` point of one call, a target
  `Argument(i)`/global, and one effect kind.
- **Output:** the substituted effect value and whether it is `MUST` or `MAY`.
  A complete answer with no matching effect returns `value=ABSENT` and
  `complete=true`.
- **Unknown behavior:** unresolved calls, invalid argument positions, unknown
  alias substitution, or incomplete summaries return `value=UNKNOWN`,
  `certainty=UNKNOWN`, and `complete=false`. Missing records in an incomplete
  summary are also unknown, never `ABSENT`.

### `return_summary(function_symbol) -> FactAnswer[ReturnSummary]`

- **Inputs:** a function definition visible in the expanded TU or a validated
  external model.
- **Output:** joined return value facts plus zero or more return relationships
  (`Parameter`, `Global`, `FreshAllocation`, or constant).
- **Unknown behavior:** unresolved declarations, unsupported returns,
  non-converged SCCs, and non-`void` fallthrough return an unknown relationship,
  `certainty=UNKNOWN`, and `complete=false`. A `void` function returns a
  complete empty return summary.

These four operations are the compatibility surface. Domain-specific helpers
such as `query_nullness` may exist only as typed views over `facts_at`; they
must preserve the same evidence, completeness, and unknown behavior.

## Worked examples

### Parameter flow

```c
void emit(const char *fmt) {
    printf(fmt);
}

void entry(const char *argument) {
    emit(argument); /* argument is modeled as an external source */
}
```

`entry.argument` is `UNTRUSTED`. Actual/formal binding copies that fact to
`emit.fmt`; `facts_at(BEFORE printf, Referent(fmt))` therefore returns
`UNTRUSTED`, `MUST`, and source/call evidence. CGULL-002 decides policy. If one
caller supplies a literal and another supplies external input, the callee's
context-insensitive input joins to `MIXED`, which is still not safe.

### Return flow

```c
char *identity(char *value) {
    return value;
}

void entry(char *input) {
    char *copy = identity(input);
    system(copy);
}
```

The summary records `Return(identity) <- Parameter(0)`. At the call site it is
substituted with `input`, so `copy` preserves input's provenance, nullness,
points-to set, allocation identity, and ownership. No fresh allocation is
invented. The source, return, and call assignments appear in evidence.

### Output-parameter side effect

```c
void make_buffer(char **out) {
    *out = malloc(32);
}

void entry(void) {
    char *buffer;
    make_buffer(&buffer);
}
```

The summary has a `MUST WRITE` and `MUST INITIALIZE` effect on
`Pointee(Param(0), 1)`. Substitution targets `Local(entry, buffer)`. After the
call, `buffer` is initialized and maybe null; its allocation alternatives are
`{NOT_ALLOCATED, LIVE}`, ownership is `{NONE, OWNED}`, and the live
allocation has exact extent 32. The malloc site in `make_buffer` remains the
single allocation identity.

### Recursion

```c
char *walk(char *value, unsigned depth) {
    if (depth == 0)
        return value;
    return walk(value, depth - 1);
}
```

The recursive SCC starts at `BOTTOM`. The base return establishes
`Return(walk) <- Parameter(0)`; the recursive call substitutes the same
relationship on the next iteration, so the SCC stabilizes without expanding a
call stack. Evidence contains one SCC/call edge rather than one node per
possible recursion depth. If the iteration budget were exhausted, the return
would be `UNKNOWN`, not the last partial summary.

### Unresolved call

```c
void entry(char *buffer) {
    plugin_transform(buffer); /* no definition or model */
    printf(buffer);
}
```

The pointer value `buffer` is not rebound by the call, but its referent may be
written or retained. The referent's provenance, literalness, initialization,
and extent become `UNKNOWN`; any allocation may be freed or escaped. The
subsequent format query returns `UNKNOWN`, `complete=false`, with
`UNRESOLVED_CALL` evidence. CGULL-002 must retain conservative behavior; it may
not classify the format as safe.

## Compatibility and versioning

- The current `Nullness.UNKNOWN` acts as a neutral value in parts of legacy
  `meet_nullness`. The new engine must introduce a separate `BOTTOM`; contract
  `UNKNOWN` is top and must not be reused as fixed-point initialization.
- Legacy missing-variable defaults (`UNINITIALIZED` and `NOT_ALLOCATED`) are
  not valid query fallbacks under this contract. Missing semantic information
  returns `UNKNOWN`.
- Adapters may project new facts into legacy `FunctionSummary` fields during
  migration, but a legacy field must not overwrite a more conservative new
  fact.
- Adding optional evidence kinds or typed convenience views is compatible.
  Changing a join, unknown-call transfer, location identity, or the four query
  operations requires an explicit contract revision and migration note.
