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
Unsupported types have unknown stride. Loop-body diagnostics are deferred, and
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
return variables, general relational bounds guards, integer-address wraparound,
and interprocedural validation summaries are outside this drop. Findings use
CWE-119 and require manual review. Juliet coverage is not yet measured.
