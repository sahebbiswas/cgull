# AST preprocessing and coverage guarantees

C-GULL's AST and Hybrid analysis modes depend on both `pycparser` and `pcpp`. These are core runtime dependencies for supported installations, not optional precision enhancements.

## Why preprocessing is required

Several AST-backed analyses rely on macro expansion before parsing. In particular, `offsetof(T, member)` must be expanded into the pointer/member expression understood by C-GULL's layout and container-recovery reasoning. If it survives preprocessing as a function call, analyses that depend on member offsets can silently lose security coverage.

A normal `pip install cgull` therefore installs both `pycparser` and `pcpp`.

## Degraded preprocessing behavior

C-GULL still retains its directive-stripped pycparser tier for resilience when preprocessing fails on source that does not require macro expansion. That fallback is supported for constructs whose semantics remain representable after directive stripping.

If AST parsing succeeds but an actual `offsetof(...)` call remains in the parsed AST, C-GULL does **not** report the file as fully analyzed. It raises a `CoverageDegradedError`, and the scan engine exposes that condition through the normal structured `scanErrors` channel. The diagnostic states that preprocessing/layout precision degraded and that container-recovery/member-layout checks are incomplete.

This behavior is intentionally centralized in the AST parser rather than in an individual security rule, so every consumer of layout/container information receives the same coverage guarantee.

## CLI and structured output

In normal terminal scans the engine prints the analysis error unless quiet mode is enabled. JSON and other structured report paths include the same diagnostic in `scanErrors`, with:

- `error_type`: `CoverageDegradedError`
- `file_path`: the affected source file
- `message`: an explanation that unexpanded `offsetof(...)` degraded preprocessing/layout precision

Because the file cannot be claimed as completely analyzed, it is reported as failed for that scan. `--fail-on-error` therefore also returns a non-zero exit status for this condition.

## Sequential and parallel scans

The coverage check is part of the public `CASTParser` used by both the in-process scanner and worker processes. The same source therefore produces equivalent coverage diagnostics with `--jobs 1` and multi-process scans.

## Remaining preprocessing limitations

The directive-stripped tier cannot reproduce arbitrary C preprocessor semantics. Macro-heavy code may still require the full `pcpp` tier to preserve the source semantics expected by AST-backed rules. C-GULL may continue with fallback parsing when that loss is not known to affect a security-critical construct, but known constructs whose required semantics are unavailable should be guarded centrally in the same manner as `offsetof` rather than silently treated as full-precision analysis.
