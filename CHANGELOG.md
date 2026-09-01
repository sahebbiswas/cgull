# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Pre-commit hook configuration (`.pre-commit-hooks.yaml`) with `--fail-on high` failure threshold and usage documentation in `README.md`.
- Support for scanning multiple target file paths or directories in `cgull scan`.

## [0.9.16] - 2026-03-29

### Added
- Dependabot configuration (`.github/dependabot.yml`) for automated pip dependency and GitHub Actions updates.

## [0.9.15] - 2026-03-28

### Added
- Standardized `CONTRIBUTING.md` guidelines, PR verification patterns, and GitHub issue templates (#256, #257).

### Fixed
- Updated rule count references to 46 across documentation and release notes (#258).

## [0.9.14] - 2026-03-20

### Added
- Allocation nullness propagation from caller to callee in CFG dataflow analysis (#237).
- Heap allocation capacity tracking enhancements and tests for `CGULL-007` (#236).

### Changed
- Consolidated packaging and build metadata into `pyproject.toml` and removed `setup.py` (#235).

### Fixed
- Refactored `FormatStringRule` (`CGULL-002`) to reduce false positives (#238).

## [0.9.13] - 2026-03-15

### Added
- Expanded NIST Juliet benchmark suite coverage to additional CWEs and enhanced reporting metrics (#233).

### Changed
- Refactored unit test suite for `NakedControlFlowRule` (`CGULL-013`) (#234).

## [0.9.12] - 2026-03-10

### Added
- Interprocedural analysis milestone documentation and scope definition (#228).

## [0.9.11] - 2026-03-05

### Added
- Control Flow Graph (CFG) representation and forward data-flow analysis engine (`cgull.cfg`) (#227).

## [0.9.10] - 2026-02-28

### Added
- Translation-Unit (`--mode tu`) mode header caching (`HeaderCache` / `HEADER_CACHE`) for preprocessed units (#216).
- `--mode {file,tu}` CLI flag and configuration file setting (`ScanMode.TU`) (#215).

## [0.9.9] - 2026-02-20

### Added
- Translation-Unit mode multi-file fixtures and cross-file line provenance tracking regression tests (#197, #198, #226).
- `--no-dedup-headers` flag for header finding deduplication across translation units (#201).

## [0.9.8] - 2026-02-15

### Added
- `PointerSubtractionSizeRule` (`CGULL-046`) for unscaled pointer subtraction in size arguments (CWE-469) (#200).
- `MissingInclusionGuardRule` (`CGULL-045`) for header files lacking inclusion guards (CWE-424) (#199).
- NIST Juliet static analysis detection quality benchmark suite (`benchmarks/run_juliet.py`) (#210).

## [0.9.5] - 2026-02-10

### Added
- `MemcpyStructMemberOverflowRule` (`CGULL-044`) for size-aware `memcpy`/`memmove`/`memset` struct member and array buffer overflow detection (CWE-787 / CWE-120) (#190).
- Recursive `#include` expansion with cycle and header guard detection for TU mode (#196).
- Structured trace logging (`--log-level trace`) to support triage of hangs and scan failures (#194).

### Changed
- Extended `strcpy()` destination size resolution to struct member access chains (#189).
- Extended `ArrayRef` and `StructRef` member chain capacity resolution for `ArrayIndexOutOfBoundsRule` (`CGULL-007`) (#188).

### Fixed
- Resolved `AttributeError` in `IncorrectPointerScalingRule` (`CGULL-040`) for compound assignment operators (#195).

## [0.9.0] - 2026-02-01

### Added
- `VariableShadowingRule` (`CGULL-043`) for variable declarations in inner scopes shadowing outer scopes (MISRA C:2012 Rule 5.3 / CWE-398) (#185).
- `DeadStoresRule` (`CGULL-042`) for dead store detection (-Wunused-but-set-variable / CWE-563) (#184).
- `UnusedLocalVariablesRule` (`CGULL-041`) for unused local variable detection with block scoping support (#183).
- Struct and union field-size table (`F1`) and expression-to-struct-type resolution (`F2`) in `CASTContext` (#186, #187).

## [0.8.45] - 2026-01-20

### Added
- Config-space static scanning engine: per-config scan execution, multi-config findings deduplication, and condition-tagged reachability (`reachable_under`) (#160, #167, #169).
- Header file (`.h`/`.hpp`) seed ingestion, JSON config profile seed format, and `compile_commands.json` ingestion (#161, #162, #163, #164).
- Pairwise covering array and bounded-exhaustive config-space expansion strategies (`--config-strategy`) (#168).
- `ConditionalFlagCollector` for preprocessor conditional flag discovery (#159).

## [0.8.28] - 2026-01-10

### Added
- `IncorrectPointerScalingRule` (`CGULL-040`) for explicit pointer offset scaling with `sizeof()` (CWE-468) (#165).

### Fixed
- Fixed multi-line statement line drift for CFG dereference findings (#176).
- Fixed realloc records replay masking double-free and use-after-free findings (#156, #157).

## [0.8.0] - 2025-12-15

### Added
- `ImproperChrootJailRule` (`CGULL-039`) for `chroot()` calls lacking `chdir("/")` checks (CWE-243) (#127).
- `ReturnStackVariableRule` (`CGULL-038`) for returning addresses of local stack variables (CWE-562) (#122).
- `StrncpyNullTerminationRule` (`CGULL-037`) for `strncpy` calls lacking proper null termination (CWE-170) (#119).
- `MemoryLeakRule` (`CGULL-036`) for un-freed dynamic memory allocations (CWE-401) (#120).
- Alias-aware lifetime tracking and intra-file interprocedural memory effect summaries (#123, #124).

## [0.7.0] - 2025-11-20

### Added
- `TOCTOUFileAccessRule` (`CGULL-035`) for time-of-check to time-of-use race conditions (CWE-367) (#94).
- `DivisionByZeroRule` (`CGULL-034`) for division or modulo by zero (CWE-369) (#92).
- `ReallocOverwriteRule` (`CGULL-032`) for `realloc` memory leaks on allocation failure (CWE-401) (#93).
- Insecure temporary file function detection (`mktemp`, `tmpnam`, `tempnam`) (CWE-377) (#95).
- CLI threshold flag `--fail-on {high,medium,low,all}` (#97).
- Per-file AST parse tier reporting and `--warn-on-fallback` CLI option (#99).

## [0.6.5] - 2025-10-15

### Added
- `SignedUnsignedComparisonRule` (`CGULL-033`) for signed/unsigned integer comparisons (CWE-195) (#86).
- `WeakBrokenCryptoPrimitivesRule` (`CGULL-031`) for broken crypto algorithms (CWE-327) (#84).
- `CommandInjectionRule` (`CGULL-030`) for OS command injection via `system`/`popen`/`exec` (CWE-78) (#76, #78).
- `SizeofOnPointerRule` (`CGULL-029`) for `sizeof()` on pointer types (CWE-467) (#70).
- `NoInsecureRandRule` (`CGULL-028`) for insecure PRNG detection (CWE-338) (#63).
- `DoubleFreeRule` (`CGULL-027`) for double free detection (CWE-415) (#38).
- `UncheckedSnprintfReturnRule` (`CGULL-026`) for unchecked `snprintf` truncation offset accumulation (#27).
- Project configuration file (`.cgull.toml` / `pyproject.toml`) and inline suppression support (#77).

## [0.6.0] - 2025-09-01

### Added
- Initial public release of C-GULL (*Code Guardian for Unchecked Logic & Leaks*).
- Core security audit rules (CGULL-001 through CGULL-025) spanning memory safety, cryptography, control flow, arithmetic, and MISRA C compliance.
- Dual analysis engine: lightweight Regex pattern scanner and AST/CFG-assisted structural analysis (`pycparser` + `pcpp`).
- Baseline and diff mode (`--baseline` and `--update-baseline`).
- Multi-format reporting (JSON, OASIS SARIF v2.1.0, Markdown, Terminal).
- Parallel scanning across CPU cores (`-j/--jobs`).
- `.cgullignore` path exclusion with gitignore glob pattern and negation support.
