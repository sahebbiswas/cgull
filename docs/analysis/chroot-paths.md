# CGULL-039: successful chroot paths

In AST and hybrid scans, CGULL-039 uses each function's structured CFG to
check whether every reachable successful `chroot()` invocation is followed by
`chdir("/")` before another function call or function exit. Repairs can be in
separate blocks or reached through valid gotos. A conditional repair, early
return, unresolved goto, or cycle that can indefinitely bypass repair retains
a finding. Each chroot invocation is checked independently.

The query assumes the invocation being checked returns zero, then follows
feasible true/false edges. It recognizes direct return-value tests, simple
local assignments and copies, zero/negative-one comparisons, logical negation,
and ordered short-circuit/comma expressions. Unknown predicates explore both
paths. Switch dispatch is conservative. Reassigned, escaped, shadowed, or
volatile result bindings do not establish a success-path proof. Calls discard
tracked values; helper functions are not modeled as repairs. Unsequenced
chroot/chdir expressions cannot prove repair ordering.

```c
int rc = chroot(path);
if (rc != 0)
    return;             /* Proven failure: no repair required. */
chdir("/");
serve();
```

The guarantee concerns reaching the repair call, not proving that `chdir`
itself succeeds. Check its return value in production code. Paths other than
the literal `"/"` and interprocedural repair helpers are unsupported. This rule
does not prove privilege dropping, descriptor closure, or broader sandbox
correctness. Unsupported conditions and the bounded state budget can produce
conservative findings.

If structured parsing fails, AST/hybrid analysis reports lexical chroot calls
without accepting a lexical chdir as proof. Explicit regex mode retains the
legacy presence/order heuristic and provides no path-sensitive guarantee.
