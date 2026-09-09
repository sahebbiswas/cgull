# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CGULL-007 consumes explicit buffer-capacity contracts from semantic call-effect models and C `T buffer[static length]` parameters, propagating proven capacities through simple pointer aliases while conservatively distinguishing element and byte counts (#404).

### Fixed
- CGULL-007 respects ordered short-circuit bounds guards at condition and body accesses, tracks true/false CFG edges, and rejects insufficient limits or invalidated index proofs (#406).
- CGULL-042 suppresses proven-pure declaration initializers overwritten before use, while retaining side-effecting initializers, later dead assignments, and scope-exit findings (#407). Lexical fallback suppression is limited to unambiguous straight-line overwrites.

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