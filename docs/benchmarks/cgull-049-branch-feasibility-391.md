# CGULL-049 branch-feasibility precision (#391)

CGULL-049 uses the shared CFG-backed integer range analysis. Branch edges are
now excluded from range joins when the current data-flow state proves the
condition to be always true or always false. This is a precision improvement;
unknown conditions continue to keep both edges.

## Supported proofs

The range engine can currently prove branch truth for:

- integer literal conditions such as `if (1)` and `if (0)`;
- side-effect-free constant comparisons and logical predicates whose operands
  reduce to singleton integer ranges;
- tracked automatic local integer values whose current range is a singleton,
  including ordinary `const` locals initialized from supported constant
  expressions;
- equivalent unary forms such as `!condition` when the operand itself is
  proven singleton.

Constant comparisons use the shared integer-promotion and usual-arithmetic-
conversion model. In particular, signed/unsigned comparisons are not folded as
plain mathematical integers when C converts a negative signed operand to an
unsigned common type.

A reassignment replaces or drops the prior singleton fact. Address-taken local
facts are invalidated across calls or indirect writes under the existing escape
model. Loop joins still widen conservatively, and an explicit
`unknown_control_flow` event (for example an unresolved direct `goto`) drops
integer range facts before later branch feasibility is considered.

## Deliberately unsupported condition forms

Static locals, globals, and volatile storage are deliberately excluded from
precise range facts used for branch feasibility. This applies both to direct
predicates and to copies into automatic locals, so a write such as
`global_flag = 1` cannot become a constant branch proof through
`local_flag = global_flag`. Comparison constraints on that unstable storage are
also kept conservative.

Branch pruning is also restricted to literals, tracked singleton identifiers,
supported unary truth forms, comparisons, and logical predicates. Standalone
constant arithmetic such as `UINT_MAX + 1U` is not used as a feasibility proof
until that path models C overflow and unsigned wrap semantics directly; both
CFG edges are retained instead.

The analysis also does **not** infer constant truth from helper-function return
values, arbitrary calls, unsupported expressions, externally changing state,
or naming conventions such as Juliet `good*`/`bad*` functions. Short-circuit
expressions are folded only when the operands needed by the current
expression-range model are themselves known. The analysis does not use a
source-level name, benchmark oracle, or presumed branch intent to discard a CFG
edge.

## Regression intent

The focused tests cover the two minimal CWE-195 reproducers from #391, folded
constant comparisons, signed/unsigned comparison semantics, overflow-prone
constant arithmetic, local constants, unknown parameters, stale reassignment,
address escape plus calls, global/static/volatile predicates, transitive copies
from unstable storage, loops, unresolved control flow, helper predicates, and
exact CWE-194/CWE-195 attribution. The change is shared range-domain behavior
rather than a Juliet-specific suppression.
