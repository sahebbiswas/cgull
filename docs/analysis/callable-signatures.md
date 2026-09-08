# Callable signature resolution

CGULL exposes a rule-neutral direct-call signature query through `cgull.ast_analyzer.resolve_direct_call_signature`.

The resolver uses parsed translation-unit declarations when available and can fall back to a small declarative standard-library signature registry when a declaration was not retained by the parser/preprocessor pipeline. It preserves fixed parameter types and optional names, return type, variadic status, whether the declaration is a true prototype, parameter pointer/array shape, and provenance. Callable signatures remain type information only: the resolver does not create CFGs, ownership summaries, trust facts, allocation effects, call effects, or other behavioral analysis state.

## Resolution precedence

Direct identifier calls are resolved deterministically in this order:

1. A lexically visible block-scope declaration.
2. A visible file-scope declaration or definition, reconciled using the existing declaration rules.
3. A compatible project/user-provided callable model, if such an extension point is configured in the future.
4. The built-in standard C/POSIX signature registry.
5. Unresolved.

The built-in registry is used only when source signature information is absent. An unspecified-parameter declaration such as `void *malloc()`, a conflicting source declaration set, or a same-named local object/function pointer is an explicit source result and therefore blocks fallback. This distinction prevents a familiar library name from overriding what the scanned source actually declares.

## Supported source forms

The query handles file-scope prototypes, function definitions, and block-scope function declarations that are lexically visible before a direct `ID(...)` call. Inner block declarations shadow outer/file declarations. Compatible redeclarations are reconciled deterministically. Conflicting visible declarations return an explicitly unresolved signature rather than selecting an arbitrary declaration.

A declaration such as `void f(void)` is treated as an explicit zero-parameter prototype. In C mode, `void f()` is treated as an unspecified-parameter declaration and therefore does not provide invented destination types for argument analysis. Variadic declarations expose only their fixed parameters; trailing variadic arguments are intentionally untyped by this query.

Parameter typedefs and qualifiers use the existing AST type infrastructure. Pointer and array shape is retained so scalar conversion rules do not accidentally treat pointer destinations as integer destinations.

## Built-in callable signatures

Issue #360 intentionally starts with a small explicit registry rather than attempting broad header emulation.

| API | Family | Modeled signature |
| --- | --- | --- |
| `malloc` | ISO C | `void *malloc(size_t size)` |
| `memcpy` | ISO C | `void *memcpy(void *dest, const void *src, size_t count)` |
| `memmove` | ISO C | `void *memmove(void *dest, const void *src, size_t count)` |
| `strncpy` | ISO C | `char *strncpy(char *dest, const char *src, size_t count)` |
| `snprintf` | ISO C | `int snprintf(char *buffer, size_t buffer_size, const char *format, ...)` |
| `read` | POSIX | `ssize_t read(int fd, void *buffer, size_t count)` |

The ISO C entries mirror the fixed parameter and return types specified by the standard library declarations; `read` mirrors its POSIX declaration. Provenance is retained as `standard-c` or `posix` on the resolved signature.

Width-sensitive typedefs remain symbolic in the registry. In particular, `size_t` and `ssize_t` are **not** converted to a byte width using the Python host ABI. Consumers resolve them through C-GULL's existing type-width infrastructure and the active parsed/configured type model. If that infrastructure cannot determine a width, type-sensitive rules must retain an unknown result rather than inventing one. The registry therefore describes the API declaration, not a target ABI.

## Extension rules

Add new built-in signatures in `cgull/ast_analyzer/standard_signatures.py` only when the declaration is stable for the supported C/POSIX surface and there is focused regression coverage. Keep target-dependent typedefs symbolic. Do not add platform-specific variants that require choosing an arbitrary ABI; unsupported or ambiguous signatures should remain unresolved until C-GULL has enough target information to select them safely.

Callable signature metadata is intentionally separate from `cgull.semantic_models` and call-effect/ownership registries. Adding a function here must not make `SemanticModelRegistry.for_function(name).is_modeled` true, suppress conservative data-flow invalidation, or imply allocation/ownership/trust behavior. Behavioral semantics require a separate explicit model in the appropriate subsystem.

## Current boundaries

The resolver currently covers direct identifier calls within one parsed translation unit plus the explicit built-in fallback table above. Function-pointer target resolution, cross-translation-unit body analysis, C++ overload resolution, general header discovery, and additional arithmetic-conversion semantics remain separate concerns. Header declarations are available when retained by the existing preprocessing/include pipeline; this query does not independently ingest headers.

## End-to-end validation

See the [external-call integration matrix and upstream audit](../benchmarks/external-conversions-376.md) for exact-CWE pipeline coverage, measured precision/recall, and residual limitations.
