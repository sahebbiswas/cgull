# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Honor short-circuit OR/AND and negated null checks, callee Is*-style truthy-implies-nonnull predicates, and cannot_access-style macros in CGULL-004 so cJSON-class false positives drop while unchecked public setters still report (#551).

### Changed
- Collect deallocation calls in `_freed_vars` with a single AST walk instead of one recursive search per configured deallocator (#547).
- Cache parsed conditional-directive IR per unique source string for the duration of a scan so reachability, simplification, and concrete resolution reuse one parse (#546).

### Fixed
- Fix `_freed_vars` to skip `None` AST children and avoid copying set-typed deallocator configs on every call (follow-up to #547).
- CGULL-011: do not treat `MACRO(type) declarator` export wrappers (e.g. `CJSON_PUBLIC(int) foo(...)`) as illegal function-pointer casts in fallback/regex analysis; AST suppression only applies when the macro match overlaps the cast's source span (#552).
- CGULL-034: do not flag NaN materialization (`NAN`, `0.0/0.0`, float zeros with exponents such as `0.0e1/0.0e1`, and casted forms such as `(double)0.0/0.0`) as runtime division-by-zero (#556).
- Group repeated CGULL-007 accesses with the same conservative CFG bounds obligation, retain related source locations in all reports, and preserve them through TU mapping and deduplication (#533).
- Model nullable non-allocation returns and non-NULL argument requirements, and report unchecked nullable locals through CGULL-004 (#538).
- Add CGULL-056 for possible reverse reads/writes below an explicitly derived logical base, including loop conditions, postfix and separated updates, and ordered lower-bound guards (#537).
- Deduplicate finalized findings by stable fingerprint across analyzer paths, configuration profiles, and translation units while preserving deterministic source attribution, confidence, fix metadata, reachability, and explicit per-TU header reporting (#532).
- Suppress CGULL-042 declaration initializers that use proven file-scope enum constants before an immediate conditional overwrite, including macro-expanded forms, while keeping shadowed or otherwise unproven identifiers conservative (#530).
- Classify CGULL-010 array bounds using C integer constant-expression semantics so constant-foldable arithmetic/bitwise and object-like macro bounds are not reported as VLAs, while const-object/runtime bounds remain VLAs (#526).
- Preserve original source provenance for TU-mode related-site diagnostics so use-after-free and memory-leak messages no longer expose expanded/preprocessed line numbers, including cross-file include sites (#525).

## [0.12.4] - 2026-09-16

### Changed
- Parallelize independent TU/source preparation for multi-worker scans, including discovery-time include expansion and parsing, with bounded process submission, deterministic project-summary merging, and conservative per-source recovery (#488).

## [0.12.3] - 2026-09-16

### Changed
- Make project-level cross-TU summary construction demand-driven by enabled rule requirements, including deterministic dependency closure, conservative custom-rule compatibility, zero-work elision for unused domains, and reproducible base/head performance instrumentation (#489).

## [0.12.2] - 2026-09-16

### Changed
- Cache TRACE enablement per file to avoid disabled logging calls in regex and AST rule loops, preserving detailed TRACE output (#494).

## [0.12.1] - 2026-09-16

### Changed
- Replace FIFO lists in CFG analyses and rule helpers with deques, and track pending fixed-point work in sets while preserving processing order (#493).

## [0.12.0] - 2026-09-15

### Fixed
- Preserve proven integer argument and return ranges across conservative same-translation-unit direct helper calls for CGULL-049, while retaining findings for mixed, external, escaped, recursive, mutated, or otherwise unresolved flows (#389).

### Changed
- Default directory and multi-target CLI scans to bounded automatic parallelism (up to eight workers), while keeping direct single-file scans sequential unless overridden. Preserve explicit `--jobs` control and programmatic scanner defaults, and report effective worker selection in human-readable and structured output (#491).
- Raise the supported Python floor to 3.12 after cross-version medium-project compatibility and performance evaluation, remove the Python 3.10 `tomli` compatibility path, and test the retained 3.12–3.14 range across Linux, Windows, and macOS (#495).

## [0.11.29] - 2026-09-14

### Added
- Show immediate, throttled live file-discovery status before directory scans begin, counting only non-ignored scan candidates and transitioning in place to normal scan progress while preserving legacy progress callbacks, structured output, diagnostic coordination, and final discovery telemetry semantics (#484).

## [0.11.24] - 2026-09-14

### Fixed
- Require regex-fallback globals to begin at lexical file scope, independently of fallback function recognition, while ignoring braces in literals, comments, inactive branches, and continued preprocessor directives so nested declarations cannot contaminate `global_variables` or trigger cross-function CGULL-043 false positives (#445).

## [0.11.23] - 2026-09-14

### Fixed
- Parse regex-fallback function definitions with balanced declarator boundaries so nested function-pointer parameters, multiline pointer returns, and supported attributes retain correct function ranges, parameters, and source coordinates without misclassifying prototypes or calls (#443).

## [0.11.22] - 2026-09-14

### Fixed
- Keep fallback CGULL-042 writes attached to the correct function body coordinate and lexical binding, including multiline statements and nested shadows. Preserve expanded coordinates separately from source provenance, withhold ambiguous locations, and require manual review for fallback dead-store fixes (#466).

## [0.11.21] - 2026-09-13

### Fixed
- Model compound assignments, increment/decrement, and indexed/member/pointer lvalue effects in the shared CFG so data-flow consumers preserve required C reads and writes and CGULL-042 avoids false dead-store reports (#464).

## [0.11.20] - 2026-09-13

### Fixed
- Warn about nonexistent or non-directory include roots with original values, resolved paths, and configuration/compile-command provenance. Retain roots for non-fatal scanning and expose warnings in JSON/SARIF results (#446).

## [0.11.19] - 2026-09-13

### Added
- Preserve per-tier parser attempt diagnostics, TU source locations, and bounded fallback reasons in JSON/SARIF metadata, debug logs, and `--warn-on-fallback` stderr output, including multiprocessing and profile scans (#444).
- Resolve otherwise unresolved system includes using the runtime `pycparser-fake-libc` dependency and a packaged Linux analysis overlay, preserving project precedence and excluding model headers from findings and source counts (#442).
- Add `cgull init [PATH]` as the canonical project setup flow, including focused/comprehensive finding profiles, interactive custom rule exclusions, include-root detection, compile database discovery guidance, and `--migrate` support for legacy `.cgullignore` and `.cgullincludes` files (#447).
- Report CLI scan-mode provenance in terminal/Markdown output and structured JSON/SARIF metadata so users and CI can distinguish explicit, configured, and target-inferred mode selection (#448).

### Changed
- Remove the advertised `init-ignore` command in favor of a single editable `.cgull.toml` configuration surface. Existing legacy project files continue to load for backward compatibility (#447).
- Infer CLI scan mode from effective targets when neither `--mode` nor project configuration selects one: any directory target uses TU mode, while file-only target lists use per-file mode. Programmatic `ScanConfig.create()` keeps its backward-compatible file-mode default (#448).

## [0.11.10] - 2026-09-10

### Added
- Add an independent conditional-directive tree with all eight conditional forms, nested branch relationships, lossless source ranges, continuation-aware token locations, symbolic conditions, recoverable structural diagnostics (#421). Existing scanner preprocessing is unchanged.

## [0.11.9] - 2026-09-10

### Added
- Add an independent symbolic preprocessor expression API with immutable Boolean nodes, distinct macro-value/definedness/opaque atoms, canonical normalization and formatting, deterministic atom enumeration, and tagged JSON serialization (#420). Scanner and concrete preprocessor behavior are unchanged.
