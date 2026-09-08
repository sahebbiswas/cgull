# Callable signature resolution

CGULL exposes a rule-neutral direct-call signature query through `cgull.ast_analyzer.resolve_direct_call_signature`.

The resolver uses parsed translation-unit declarations rather than requiring a callee body. It preserves fixed parameter types and optional names, variadic status, whether the declaration is a true prototype, parameter pointer/array shape, and provenance (`file-declaration`, `block-declaration`, `definition`, or `conflicting-declarations`). Declaration-only callees remain type information only: the resolver does not create CFGs, ownership summaries, trust facts, or other body-derived analysis state.

## Supported forms

The query handles file-scope prototypes, function definitions, and block-scope function declarations that are lexically visible before a direct `ID(...)` call. Inner block declarations shadow outer/file declarations. Compatible redeclarations are reconciled deterministically. Conflicting visible declarations return an explicitly unresolved signature rather than selecting an arbitrary declaration.

A declaration such as `void f(void)` is treated as an explicit zero-parameter prototype. In C mode, `void f()` is treated as an unspecified-parameter declaration and therefore does not provide invented destination types for argument analysis. Variadic declarations expose only their fixed parameters; trailing variadic arguments are intentionally untyped by this query.

Parameter typedefs and qualifiers use the existing AST type infrastructure. Pointer and array shape is retained so scalar conversion rules do not accidentally treat pointer destinations as integer destinations.

## Current boundaries

The resolver currently covers direct identifier calls within one parsed translation unit. Standard-library fallback signatures, function-pointer target resolution, cross-translation-unit body analysis, C++ overload resolution, and additional arithmetic-conversion semantics remain separate concerns. Header declarations are available when they are retained by the existing preprocessing/include pipeline; this query does not independently ingest headers.
