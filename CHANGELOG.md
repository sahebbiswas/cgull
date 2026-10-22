# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Behaviour change:** `--fail-on` (and `--fail-on-high`, `[output].fail_on`, the action's `fail-on`) no longer counts `FALLBACK`-confidence findings from structural engines (`AST`, `AST-CFG`, `Interprocedural`, `Symbolic preprocessor`); they stay in text, Markdown, JSON, and SARIF reports with `impact` and `confidence` intact, and a stderr note gives the count left out of the gate. New `--strict-confidence` flag, `[output].strict_confidence` config key, and `strict-confidence` action input restore the severity-only gate. `Regex`-engine findings and `LIMITED` confidence still count. Text and Markdown summaries split High findings into full-confidence and fallback-confidence, and `docs/reporting-and-ci.md` documents the gate × confidence matrix (#589).
- Add CGULL-057 (CWE-273) for privilege-dropping calls (`setuid`, `setgid`, `seteuid`, `setegid`, `setresuid`, `setresgid`) whose return value is discarded: bare statements, braceless `if`/`else`/loop bodies, `for` initializers and steps, dropped comma-expression operands and explicit `(void)` casts report, while results that are assigned, compared, returned, short-circuited on, used as a condition, or passed to another call do not. The regex and lexical-fallback paths judge only the current statement (including statements split across lines) and ignore prototypes, member calls and macro definitions (#591).
- Declare `cpre>=0.11.0,<0.12` as an explicit runtime dependency and introduce `cgull.preprocessor.cpre_api` as the pinned public-API boundary (expressions, lossless conditional structure, exact Boolean proofs/witnesses) with smoke tests and ownership documentation for the #436 migration (#436).
- Opt-in persistent content-addressed per-file result cache for repeat scans (`--cache-dir` / `--cache-path` / `CGULL_CACHE_DIR`, disable with `--no-cache` / `CGULL_NO_CACHE`); keys cover canonical path + source + expanded TU text, config/rule fingerprint, semantic-model digest, and C-GULL version, with atomic best-effort writes, path rebinding on hit, and corrupt-entry misses (#545).

### Changed
- Document the versioning policy: every pull request merged to `main` bumps `cgull.__version__` once (patch for fixes, precision improvements, docs and tooling; minor for new rules and features and, while `0.x`, deliberate compatibility breaks; major only with maintainer agreement), including how stacked pull requests are versioned, what counts as public, and how the release checklist relates to per-PR bumps (CONTRIBUTING.md, `docs/releasing.md`, README) (#594).
- Reuse session-owned structural CFGs and equivalent pre-dataflow event-annotation templates across rules, summaries, ownership, and integer-range consumers, while keeping isolated consumer views and the #582 annotated memory-rule template cache (#583).
- Share post-dataflow memory-rule CFGs per AST inputs, copy CFG basic-block topology on analysis clones, and reuse project-summary sessions across domains/rounds to cut residual rule CFG fanout and cross-TU summary rebuild work (#581).
- Reduce residual large-function/TU scan cost by copying CFG basic-block topology on analysis clones, reusing session function summaries for ownership and CGULL-042 consumers, and using a worklist for summary output-initialization (#548).
- Reuse whole-TU function summaries per session and effective semantic-input key across ownership, dead-store, MISRA/style, and custom memory-rule consumers; isolate returned results and invalidate on imported-summary or registry changes (#544).
- Add `scan/rules --profile focused|comprehensive`, include CGULL-018 in focused policy exclusions, and separate security/correctness from policy/quality report counts without changing severity or CI thresholds (#557).
- Document focused security defaults, baselines, and the cJSON corpus budget checklist; human reports also label **security actionable** vs **policy/quality** per finding (#561).

### Fixed
- CGULL-004: `suggested_fix_replacement` now follows the enclosing function's return type instead of always proposing `return -EINVAL;`: `return NULL;` for pointer returns, `return;` for `void`, and the integer error return only for signed integer types (`int`, `long`, `ssize_t`, `intN_t`, ...). For `double`/`float`, unsigned or `size_t`-like types, booleans, structs and unresolved typedefs the finding is `manual_review` with no replacement, so no suggestion can fail to type-check or mean success. Export-macro wrappers such as `CJSON_PUBLIC(const char*)` are unwrapped on the fallback path. Only `SAFE_FIX` findings are ever applied by `--fix`, so CGULL-004 still never edits source (#586).
- CGULL-004: the regex-fallback path (used when a file takes the fallback parser tier, for example because an export macro such as `CJSON_PUBLIC(type)` is undefined) now honors the guards the CFG path honors: enclosing `while`/`for`/`if` conditions, dominating early-exit guards anywhere in the function (including `if (!IsFoo(p)) return NULL;`), same-statement short circuits (`p && p->x`, `!p || p->x`, `p ? p->x : 0`), the `else` branch of `if (p == NULL)`, and same-file `Is*`-style predicates that return a falsy constant for a NULL parameter. A brace-less `if (!p) return -1;` no longer marks the following line as a known-NULL dereference. Unguarded uses, guards that do not exit, and guards in a block that closed before the use are still reported (#587).
- CGULL-006: treat allocation-size accumulations that feed malloc/realloc/calloc as overflow-sensitive even after partial INT_MAX-style gates (cJSON ensure()-style `needed += offset + 1`); require SIZE_MAX-relative guards to match operands/operation; ignore MIN_* / wrong-direction numeric bounds as overflow proofs; join multiline alloc calls; detect `sizeof(T) * count` size args and implicit `calloc` argument products (#560).
- CGULL-048: credit post-`sprintf` length-vs-capacity reject defenses (cJSON `print_number` pattern) so fail-closed checks suppress the overflow finding while unchecked uses still report (#562).
- CGULL-004: report additive pointer arithmetic (`p + off`, `off + p`, `p - off`) and nested forms such as `*(p + i)` when the pointer may be NULL, while keeping guarded uses like `if (p) return p + off;` silent (#559).
- CGULL-049: restore ISO unsigned/`size_t` semantics for fake_libc `typedef int size_t` only when that typedef is the *source* of a conversion into a signed destination, so accumulate-then-cast-to-int patterns such as `cJSON_GetArraySize` report CWE-196 without treating signed→`size_t` (Juliet CWE-195) as conversions; still suppress when a dominating `size <= INT_MAX` (or equivalent) guard proves the value fits (#558).
- CGULL-042: join-aware fallback liveness for mutually exclusive if/else (and else-if) arms so sibling-arm stores read after the join are not reported as dead, while same-arm overwrites and post-join kills remain findings (#554).
- Honor sizeof-bounded loops, can_access_at_index-style cursor guards, and ensure()/realloc-sized buffer returns in CGULL-007 so cJSON-class false positives drop while genuine OOB and needs-context cases like parse_hex4 remain (#553).
- Honor short-circuit OR/AND and negated null checks, callee Is*-style truthy-implies-nonnull predicates, and cannot_access-style macros in CGULL-004 so cJSON-class false positives drop while unchecked public setters still report (#551).

### Changed
- Collect deallocation calls in `_freed_vars` with a single AST walk instead of one recursive search per configured deallocator (#547).
- Cache parsed conditional-directive IR per unique source string for the duration of a scan so reachability, simplification, and concrete resolution reuse one parse (#546).
- Cache immutable AST-stable CFG event facts per analysis session and reuse summary-dependent overlays while relevant callee effects are unchanged (#543).

### Fixed
- Fix `_freed_vars` to skip `None` AST children and avoid copying set-typed deallocator configs on every call (follow-up to #547).
- CGULL-011: do not treat `MACRO(type) declarator` export wrappers (e.g. `CJSON_PUBLIC(int) foo(...)`) as illegal function-pointer casts in fallback/regex analysis; AST suppression only applies when the macro match overlaps the cast's source span (#552).
- CGULL-034: do not flag NaN materialization (`NAN`, `0.0/0.0`, float zeros with exponents such as `0.0e1/0.0e1`, and casted forms such as `(double)0.0/0.0`) as runtime division-by-zero (#556).
- CGULL-023: require a proven use on a path where a local is not definitely assigned (member/element stores, memset/sprintf destinations, and static zero-init), instead of flagging declaration-without-initializer (#555).
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
