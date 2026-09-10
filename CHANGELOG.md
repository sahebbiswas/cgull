# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.9] - 2026-09-10

### Added
- Add an independent symbolic preprocessor expression API with immutable Boolean nodes, distinct macro-value/definedness/opaque atoms, canonical normalization and formatting, deterministic atom enumeration, and tagged JSON serialization (#420). Scanner and concrete preprocessor behavior are unchanged.

### Fixed
- CGULL-039 checks every successful chroot path for chdir("/") using CFG reachability, including bypasses, result tests, and loops/gotos (#364).

## [0.11.7] - 2026-09-09

### Added
- Make `pycparser` and `pcpp` core runtime dependencies so normal installs retain macro-expanded AST coverage, and surface surviving unexpanded `offsetof(...)` calls as structured coverage-degradation errors (#401, #408).
- Add explicit semantic-model and C `T buffer[static length]` capacity contracts for CGULL-007, including conservative alias propagation and element/byte unit handling (#404, #413).
- Add conservative affine relation facts so CGULL-007 can prove bounds for related loop induction variables without assuming independently updated variables remain equivalent (#405, #414).
- Share compatible direct-call memory, ownership, value, and security summaries across scanned translation units with deterministic convergence and conservative linkage/configuration isolation (#365, #415).
- Infer promoted integer expression types for CGULL-049 conversion sinks, covering arithmetic, shifts, casts, comparisons, and conditional expressions using C integer promotions and usual arithmetic conversions (#390, #417).

### Fixed
- Preserve loop-carried reads in CGULL-042 lexical fallback analysis so assignments feeding `while`/`for` loop conditions are not incorrectly reported as dead stores (#402, #409).
- Route pcpp `#error`/`#warning` diagnostics through C-GULL's structured diagnostics instead of allowing raw preprocessor output to corrupt CLI/structured output (#403, #410).
- Suppress proven-pure defensive declaration initializers in CGULL-042 only when every path overwrites them before use, while preserving side effects and genuine later dead stores (#407, #411).
- Respect ordered short-circuit bounds guards in CGULL-007, track CFG edge polarity, and invalidate stale index proofs after relevant mutations or calls (#406, #412).
- Correct Juliet attribution for unprefixed `badSink` helpers and split-flow oracle discovery without relaxing exact-CWE matching or double-counting good helpers (#388, #416).

## [0.11.0] - 2026-09-08

### Added
- Flow-sensitive resolution of simple local function-pointer targets, including deterministic multi-target joins and integration with the translation-unit call graph while preserving conservative unresolved behavior (#366).
- Explicit unresolved-`goto` CFG events and structured diagnostics so missing labels no longer silently terminate analysis paths; affected downstream facts degrade conservatively (#363).

### Changed
- Refactored CFG implementation into functionally cohesive modules for AST event extraction, graph topology, lattice domains, and legacy dataflow while preserving established compatibility imports and behavior (#393).
- Interprocedural consumers now use resolved possible callees for indirect calls so lifetime, dereference-safety, validator, and related summaries participate after function-pointer resolution (#366).

## [0.10.8] - 2026-09-08

### Added
- Manifest-driven external-call conversion integration coverage with exact CWE/argument locations, signature degradation checks, and reproducible upstream evidence for CGULL-049 (#376).

## [0.10.7] - 2026-09-08

### Added
- `CGULL-053` reports distinct-object pointer subtraction and memory uses after lossy address transformations or unproven container recovery. Shared range facts preserve supported identity/constant-offset round trips and proven member containment, including direct-call access requirements (#375).

## [0.10.6] - 2026-09-08

### Added
- Cached pointer-range requirements across direct calls and wrappers, evaluated against each caller's object bounds, validated intervals, enclosing guards, and provenance. Shared SCC fixed-point evaluation bounds recursion and preserves mixed safe/unsafe call contexts (#374).

## [0.10.5] - 2026-09-08

### Added
- `CGULL-052` detects pointer range comparisons relying on unproven endpoint arithmetic, including unsigned address temporaries and unordered unsigned distance checks (#373).

### Fixed
- Reject unsafe endpoint arithmetic before establishing enclosing pointer bounds. Constant offsets now require independent capacity evidence; guarded lengths retain branch-local safety facts.