# Rule reference

C-GULL rule identifiers are stable diagnostic identities. Use the CLI as the authoritative installed-version catalog:

```bash
cgull rules
```

The command reports each active rule's ID, name, impact, category, CWE mapping, implementation method, and analysis engine from the same metadata used by the scanner. This avoids a manually duplicated table drifting behind the code as rules evolve.

## Rule families

The current registry covers security and correctness concerns including:

- banned/dangerous APIs and unsafe conversions;
- format strings and command injection;
- dynamic allocation, nullness, ownership, leaks, double free, use-after-free, and stack lifetime;
- array bounds, pointer arithmetic, integer arithmetic, signedness, VLAs, and object sizing;
- cryptographic/sensitive-memory and timing patterns;
- TOCTOU and selected environment/sandbox checks;
- external-data trust boundaries;
- control-flow, dead/unused code, inclusion guards, and selected MISRA/style checks.

Rule implementations live under `cgull/rules/` and are registered in `cgull/rules/__init__.py`.

## Configuration by rule ID

Disable a rule with a recorded justification:

```toml
[rules]
skip = { "CGULL-019" = "Not required by this project's coding standard" }
```

Override severity:

```toml
[rules.severity]
CGULL-024 = "high"
```

Suppress a single intentional occurrence in source:

```c
legacy_call(); // cgull-ignore: CGULL-001
```

See [Configuration](configuration.md) and [Project files and suppressions](project-files.md).

## CWE mappings and benchmark credit

A rule's CWE metadata describes the weakness class it is intended to identify. Benchmark mappings are maintained separately so detection-quality accounting can credit every applicable signal without conflating a CWE mapping with demonstrated recall.

For contributor guidance on adding or changing rules, see [Repository extension](repository-extension.md).

## CGULL-049: unsafe integer conversion

CGULL-049 reports value-changing integer conversions across explicit casts,
declaration initializers, ordinary assignments, direct argument binding, and C
compound assignments. Compound-assignment coverage includes `+=`, `-=`, `*=`,
`/=`, `%=`, `<<=`, `>>=`, `&=`, `^=`, and `|=`.

For compound assignments, the rule models the C integer promotions and usual
arithmetic conversions used by the operator, then checks conversion of the
operation result back to the left-hand-side type. This lets it identify both
unsafe operand signedness changes and result truncation that are hidden by the
compact compound syntax. Shift assignments use the promoted left operand as the
operation result type, matching C shift semantics.

Diagnostics retain the existing conversion classes: unexpected sign extension
uses CWE-194, negative signed-to-unsigned conversion uses CWE-195,
out-of-range unsigned-to-signed conversion uses CWE-196, and width-reducing
truncation uses CWE-197. CFG-backed range facts suppress a finding only when the
actual value being converted is proven representable in the destination type.
An independently reportable explicit cast inside a compound assignment owns the
diagnostic so the enclosing compound operation does not duplicate it.

The rule is intentionally limited to integer semantics. Floating-point
conversions, vector types, overloaded C++ operators, and unresolved/non-integer
compound operations are not inferred.

## CGULL-050: pointer outside object bounds

This AST rule reports constant pointer derivations that are definitely outside
an originating object's interval. It supports `p + n`, `p - n`, `+=`, `-=`,
`&p[n]`, simple nested arithmetic, aliases, pointer casts, and typedefs. Offsets
use the pointer element width; byte casts switch to byte scaling.

For `int a[10]` and `int *p = &a[3]`, `p - 4` reports, while `p - 3` and
`p + 7` are legal formations. The latter is one-past: reading `*(p + 7)` or
writing `p[7]` reports. `sizeof(*p)` and `&*p` are not accesses.

Pointer formation findings use **CWE-823**. Proven reads use **CWE-125**, and
writes use **CWE-787**. Compound memory assignments are classified as writes.
Diagnostics include the origin, byte offset or interval, object extent, and
access width when relevant. No automatic fix is offered.

The shared analysis retains an exact object extent separately from minimum
accessible capacity. Local constant-size arrays and constant-size allocations
can supply exact extents; caller-derived minimum capacities cannot. A joined
offset interval reports only if every possible offset violates the boundary.
Unknown offsets and incompatible origins do not report.

This first drop is intraprocedural and uses the shared domain's scalar width
model (including 8-byte `long` and pointer widths), not target ABI discovery.
Unsupported types have unknown stride. Loop-body diagnostics in CGULL-050 are deferred (CGULL-056 separately checks possible reverse lower-bound accesses), and
unstable loop facts widen to unknown. Functions with `goto`, labels, `switch`,
shadowed local names, address-taken local variables, or nested update side
effects are conservatively excluded from definite diagnostics until those
effects are modeled. General subobject bounds, API validation, interprocedural
propagation, and integer-to-pointer recovery are outside this rule's scope.
Focused corpus coverage is provided; Juliet coverage is **not yet measured**.

## CGULL-051: access outside a validated pointer range

This AST rule checks actual memory uses against the byte intervals established
by [configured pointer/length validators](trust-boundary-semantic-models.md#pointer-interval-validators).
Validating `[p, p + 16)` covers a four-byte read at `p + 12`, but not at `p + 14`
or `p - 4`. Forming a derived pointer alone does not trigger this rule.

Diagnostics distinguish accesses before/after the validated range from uses
whose offset or width cannot be established. Unknown widths are never claimed
safe. Unrelated unknown pointers without a successful validation context do not
report. A known enclosing object can prove accessibility independently; definite
object-bound violations are left to `CGULL-050` to avoid duplicate reports.

The analysis is intraprocedural and shares `CGULL-050`'s control-flow and scalar
width limitations. Structs/unions use natural alignment under that width model;
packed layouts, bitfields, and flexible arrays remain unsupported. Validator lengths currently require integer constants or
supported `sizeof` expressions. Unknown lengths establish no concrete interval.
Pointer member accesses use known field layout where available; unsupported
layout produces an explicit unknown-width/offset diagnostic. Saved validator
return variables, integer-address wraparound,
and interprocedural validation summaries are outside this drop. Findings use
CWE-119 and require manual review. Juliet coverage is not yet measured.

Enclosing-range guards can also prove accessible bytes. For example,
`if (p < base + sizeof(int)) return;` establishes enough space before `p` for
an integer, while `if (p + 16 > end) return;` establishes forward capacity.
Reversed comparisons and compatible signed pointer-distance forms are supported.
These proofs apply only on the guarded path and are invalidated when a dependent
pointer, boundary, or size changes. Unknown/volatile sizes and ambiguous unsigned
distance comparisons remain unproven. See the
[shared pointer fact contract](interprocedural-fact-query-contract.md#pointer-formation-and-access-observations).


## CGULL-052: unsafe pointer range endpoint

Reports bounds comparisons that rely on address addition/subtraction without
independent non-wrapping evidence, including integer-address temporaries.
Ordinary pointer arithmetic outside a range comparison is not reported by this
rule. Small constants still need known object/validated capacity.

```c
// Reported: len is unconstrained.
return p + len <= end;

// Accepted: subtraction is reached only after endpoint ordering succeeds.
if (p > end) return false;
return len <= (size_t)(end - p);
```

Facts are branch-local and invalidated by reassignment or address escape.
Like the shared pointer analysis, unsupported control flow (including goto,
switch and shadowed identifiers) does not produce definite events. Arbitrary
pointer/integer provenance recovery and target ABI inference remain outside
this rule's scope.

## CGULL-053: unproven pointer provenance

Reports subtraction between pointers to distinct known objects (CWE-469), and
memory accesses after provenance loss or unproven `container_of` recovery
(CWE-823). Casts alone do not produce a finding. Unknown pointer origins do not
establish that two pointers belong to different objects.

The shared pointer-range model retains identity through address-width unsigned
integer casts (`uintptr_t`, equivalent typedefs, and unsigned long types under
its existing 64-bit width model). Constant integer offsets retain evidence only
within a known object; bitwise operations, narrowing, and unsupported arithmetic
discard object extents and validation guarantees. Pointer differences are never
reused as pointer aliases. CGULL-046 continues to check element-to-byte scaling;
both rules can report when subtraction has two independent defects.

Natural-layout member addresses and expanded `offsetof` support conventional
`container_of` recovery. The pcpp path supplies a default `offsetof` expansion;
source macro definitions can override it. A proven member relationship survives
aliases and pointer casts. An external member pointer alone supplies no enclosing
object proof. Direct-call requirements carry provenance weakening to callers and
can discharge container recovery against a known caller member relationship.

Limitations follow the shared domain: unsupported control flow suppresses events,
unknown/packed/bitfield layouts do not establish containment, arbitrary pointer
tagging is unsupported, and this is not a general alignment or points-to rule.
Known misaligned offsets into suitably aligned local objects weaken provenance;
unknown alignment never creates a new guarantee. Inferred pointer return values
and cross-call comparisons of two formal pointer origins are not modeled.

## Defensive local initialization (CGULL-042)

CGULL-042 skips a declaration initializer when it can prove the initializer is side-effect-free. This includes literal values, null pointer constants, unshadowed file-scope enum constants, simple object addresses, and constant aggregate initializers. Object-like macros are covered when preprocessing expands them to one of those proven forms; unresolved identifiers remain conservative. Calls, mutations, and unproven reads remain eligible for findings, as do later redundant assignments.

Lexical fallback applies this policy to verified declaration writes, including constant array initializers. Findings retain the concrete lexical binding and the starting line of the write statement. TU expansion restores the original file, line, and snippet once, before inline suppression and fingerprinting. Ambiguous compact statements or candidates without a verified write are withheld. Fallback dead-store findings require manual review; they never offer automatic deletion.


## CGULL-056: unguarded reverse pointer walk

This AST rule reports a **possible** read (CWE-125) or write (CWE-787) below a
logical base established by an explicit pointer alias or derivation. For example,
`char *p = base; use(*--p);` and the reverse trim loop
`char *p = base + strlen(base); while (isspace(*--p)) ;` report. `strlen` does
not establish a positive length: empty input remains possible.

The shared pointer analysis has a separate lower-bound domain that preserves
observations in `while`, `do` and `for` conditions, bodies and steps. Descending
loop offsets widen before a final observation pass. Prefix decrement affects the
current access; postfix decrement affects subsequent uses/iterations. A single
`use(*p--)` starting at the base is not an underflow read. Separated updates,
constant pointer subtraction, aliases, and constant array subscripts are covered.

Check the lower bound **before** the decrement/access, for example:

```c
while (p > base && isspace((unsigned char)*--p)) ;
```

Ordered short-circuit guards, reversed comparisons and early-exit guards are
recognized. `p >= base` is sufficient for `*p--`, but not `*--p`. A guard checked
after the access does not protect it. `sizeof` and address formation are not
memory accesses.

This medium-false-positive rule does not infer the allocation boundary from an
incoming pointer or change CGULL-050's definite-only contract. An unrelated
external pointer without an explicit base relationship is not reported. An
incoming pointer may itself point into a larger allocation; findings require
manual review of the logical base contract. The analysis is intraprocedural and
does not prove iteration counts or data-dependent termination. Pointer casts
lose the relationship; pointer-variable address escapes lose that variable's
facts. Functions with shadowing, `goto`, labels or `switch` are conservatively
excluded. Complex control-flow exits and interprocedural cursor updates are not
fully modeled. Behavioral corpus coverage is provided; Juliet coverage is
**not yet measured**.

## Nullable pointers (CGULL-004)

Local pointers include results of calls with known nullable return contracts,
including same-TU helper summaries. CGULL-004 reports definite or possible NULL
values at `*p`, `p[i]`, `p->field`, and modeled non-NULL argument uses such as
`strcmp(p, other)`. Dominating guards and expression-local short-circuit or
conditional guards suppress these findings. Unknown call results alone do not
establish nullable evidence. This requires AST/CFG analysis; lexical fallback
retains its direct-NULL and parameter checks. CGULL-003 remains allocation-specific.

See [nullable call contracts](trust-boundary-semantic-models.md#nullable-call-contracts).
