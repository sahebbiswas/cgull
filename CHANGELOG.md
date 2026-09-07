# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Extended `CGULL-049` to detect implicit integer narrowing in declaration initialization, ordinary assignment, and direct argument-to-parameter binding when the callee type is available in the current translation unit (#348).
- Structured CFG call metadata with ordered arguments, result bindings, unresolved indirect-call markers, and original source provenance (#241).

## [0.9.20] - 2026-09-02

### Added
- Behavioral corpus coverage for all 46 registered rules, including positive, negative, and edge-case fixtures for the 18 previously uncovered rules (#247).

### Changed
- Raised the enforced rule behavioral coverage threshold from 40% to 100%.

## [0.9.18] - 2026-03-30

### Added
- Composite GitHub Action (`action.yml`) wrapping `cgull scan` with SARIF upload support and usage documentation in `README.md`.
- Action self-test GitHub Actions workflow (`.github/workflows/action-test.yml`).
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
