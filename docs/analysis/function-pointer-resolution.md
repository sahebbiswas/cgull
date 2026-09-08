# Function-pointer target resolution

C-GULL performs a bounded, flow-sensitive target analysis for indirect calls before building the translation-unit call graph. The purpose is to recover interprocedural edges when a callback target is locally provable without introducing whole-program points-to analysis.

## Supported forms

The resolver tracks local function-pointer variables through:

- direct initialization from a visible function, such as `fn_t cb = helper;`
- later direct assignment, such as `cb = helper;`
- direct aliases between tracked local function-pointer variables
- control-flow joins; identical targets remain a singleton and different known targets form a deterministic sorted target set

A singleton target is exposed as the call's effective `direct_callee` for existing summary consumers while the call remains marked syntactically indirect. Multi-target calls retain all candidates in `resolved_callees` and contribute an edge to every visible target in the TU call graph.

## Conservative behavior

Unknown assignments dominate a join. Function-pointer parameters, external values, unsupported expressions, and calls whose target cannot be proved remain unresolved. C-GULL does not guess a target from spelling alone.

The resolver intentionally does **not** implement arbitrary heap-stored callbacks, pointer arithmetic, dynamic loading, linker aliases, C++ virtual dispatch, or general Andersen/Steensgaard-style points-to analysis. Struct/dispatch-table field resolution is deferred until the AST/type model can prove those field values without speculative alias analysis.

Cross-translation-unit target lookup is likewise separate from this intra-TU analysis and can reuse the same target metadata once a project-level summary index is available.
