# CFG architecture

The `cgull.cfg` package is organized by responsibility so control-flow changes can remain local and data-flow consumers do not need to understand pycparser details.

## Dependency direction

The intended dependency direction is:

`model -> ast_events -> construction -> dataflow -> queries / analyses`

Higher-level analyses may consume the stable CFG API, but construction and generic data-flow code must not depend on security rules.

## Module responsibilities

### `model.py`

Defines shared CFG/domain data types such as events, calls, source locations, basic blocks, and fact enums. New graph-independent value objects belong here.

### `ast_events.py`

Owns pycparser-specific expression inspection and conversion of AST nodes into CFG event facts. This includes reads/writes, dereferences, null facts, allocation/free/realloc payloads, call metadata, function-pointer recognition, and expression-level helpers used by data-flow.

Do not put graph traversal, node creation, edge wiring, or rule-specific policy here.

### `construction.py`

Owns structured statement-to-graph construction and the stable `build_cfg()` entry point. It handles compounds, branches, loops, switch/case, labels/goto, break/continue, returns, ternary lowering, and edge facts. AST event semantics are delegated to `ast_events.py`.

Private AST helper names that historically existed in `construction.py` are temporarily imported there for compatibility; new code should import them from `ast_events.py` when internal access is necessary.

### `dataflow.py`

Owns the CFG graph container, basic-block construction, fixed-point propagation, and query methods for the legacy nullness/initialization/allocation domains. New AST extraction logic does not belong here.

### Specialized analyses

Ownership, value facts, integer/pointer ranges, interprocedural propagation, and security provenance remain separate consumers of the core CFG. They should depend on the stable graph/event API rather than implementation details of construction.

## Adding CFG functionality

When adding a feature, place AST recognition in `ast_events.py`, structured edge/control-flow behavior in `construction.py`, generic propagation in `dataflow.py`, and analysis-specific semantics in the corresponding specialized module. Avoid lazy imports as a dependency-management mechanism; if two layers require each other, extract the shared contract downward instead.

Behavior-neutral refactors should preserve `build_cfg`, event metadata, edge structure, basic blocks, and data-flow query results. Any semantic change discovered while reorganizing code should be handled separately so review can distinguish architecture work from analyzer behavior changes.
