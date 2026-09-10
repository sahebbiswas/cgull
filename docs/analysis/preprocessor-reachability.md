# Preprocessor branch reachability (CGULL-054)

`CGULL-054` is a **Low** severity rule in the **Control Flow & Logic** category. It reports preprocessor branches that the symbolic Boolean model can prove unreachable, and conditional directives whose condition is already guaranteed whenever that branch is reached. Findings map to CWE-561 (dead code) and require manual review.

The rule consumes the shared `cgull.preprocessor` conditional-directive tree and exact ROBDD query API. It does not run a second directive parser and does not change active-source preprocessing semantics.

For each `#if` / `#elif` / `#else` chain, C-GULL combines the surrounding parent condition with the negation of conditions already handled by earlier siblings. A conditional branch is reported as unreachable only when that effective condition is provably unsatisfiable. A reachable condition is reported as redundant when the remaining branch context logically implies it.

Examples:

```c
#if A
#elif A && B   // CGULL-054: unreachable; A is already false here
#endif
```

```c
#if A
#  if A        // CGULL-054: redundant; parent already guarantees A
#  endif
#endif
```

```c
#if A
#elif B        // clean: !A && B is satisfiable
#endif
```

Diagnostics use the original directive source location, including line and column, and include the effective Boolean context used for the proof. Opaque C predicates remain independent Boolean atoms; C integer-expression semantics are not inferred. ROBDD resource exhaustion fails conservatively, so it cannot create a dead/redundant finding. Malformed branch conditions similarly stop reasoning for the affected sibling chain rather than making assumptions about later branches.
