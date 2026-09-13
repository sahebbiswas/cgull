# Analysis model

C-GULL combines lightweight lexical checks with structural, control-flow, data-flow, and interprocedural analysis. This document explains the operational choices that affect coverage and confidence.

## Engines

`cgull scan --engine` accepts:

- `hybrid` — default; lets the rule set use the strongest applicable analysis while retaining lightweight checks;
- `regex` — lightweight lexical/pattern-oriented analysis;
- `ast` — structural/AST-oriented analysis.

For normal use, keep the `hybrid` default unless you are deliberately measuring or debugging one analysis path.

## File mode and translation-unit mode

The CLI selects scan mode with this precedence:

1. an explicit `--mode file|tu`;
2. a mode configured in the discovered `.cgull.toml` or `pyproject.toml`;
3. target-based inference.

When inference is used, any directory target selects translation-unit (TU) mode. A target list containing only source files selects file mode. This means `cgull scan .`, `cgull scan src/`, mixed file/directory scans, and the no-target `cgull scan` form naturally use TU mode, while direct file scans remain lightweight.

File mode analyzes discovered files individually:

```bash
cgull scan src/main.c
cgull scan . --mode file
```

Translation-unit (TU) mode expands resolvable project includes and preserves a provenance map back to original files:

```bash
cgull scan .
cgull scan . --mode tu
```

Explicit overrides continue to work in either direction. The terminal scan summary reports both the selected mode and whether it came from the command line, configuration, or target inference. JSON and SARIF reports expose the same provenance as structured run metadata.

The programmatic API is intentionally different: `ScanConfig.create()` retains `ScanMode.FILE` as its backward-compatible default. Target-based inference is a CLI behavior only.

TU mode is useful when a rule needs declarations, macros, wrappers, or effects defined in project headers. Configure include roots with `.cgullincludes`, `.cgull.toml`, or build metadata.

Header guards, `#pragma once`, include cycles, expansion depth, source provenance, and repeated headers are handled by the TU expansion layer. Header findings are deduplicated across TUs by default; use `--no-dedup-headers` when investigating each TU occurrence separately.

## Structural parser tiers

C source is often not directly parseable without preprocessing. C-GULL uses progressively more tolerant structural paths so a difficult file does not crash the entire scan. Where optional preprocessing/parser support is installed, it can use expanded/preprocessed source; otherwise it can fall back to lighter structural extraction.

The result records parse-tier information in file summaries. To make parser fallback a CI quality condition:

```bash
cgull scan . --warn-on-fallback
```

This is intentionally separate from vulnerability severity. A fallback means reduced structural confidence, not necessarily that a vulnerability was found.

## Include resolution and boundaries

Quote includes search the source directory before configured include roots. Angle includes search configured roots. By default, include expansion is contained to trusted source/project/include roots so path traversal and symlink escapes do not unexpectedly widen the analysis boundary.

See [Project files and suppressions](project-files.md) for `.cgullincludes`.

## Preprocessor configuration profiles

Conditional compilation can expose different code paths under different build configurations. Discover flags with:

```bash
cgull flags .
```

or:

```bash
cgull scan . --list-flags
```

C-GULL distinguishes presence-style flags from value-comparison flags and can expand analysis profiles with:

- `baseline`;
- `one-at-a-time` (CLI default);
- `pairwise`;
- `exhaustive`.

Example:

```bash
cgull scan . --config-strategy pairwise
```

Bound exhaustive expansion with:

```bash
cgull scan . --config-strategy exhaustive --exhaustive-threshold 8
```

Configuration seeds can come from headers/directories/JSON through repeated `--config-seed` arguments. A `compile_commands.json` database can also provide build-derived configuration:

```bash
cgull scan . --compile-commands build/compile_commands.json
```

## Interprocedural analysis

C-GULL has a shared interprocedural analysis layer for facts that must cross function boundaries, including call effects, ownership, provenance, and other rule-specific queries. Analysis sessions cache shared translation-unit facts so multiple rules can reuse the same work.

Multi-file AST/hybrid scans also import compatible direct-call summaries across TUs for memory, ownership, value, and trust analysis. See [project-level direct-call summaries](analysis/project-summaries.md) for linkage, configuration isolation, recursive limits, and unsupported cases.

For implementation details and extension contracts, see:

- [Interprocedural analysis](interprocedural-analysis.md)
- [Interprocedural fact query contract](interprocedural-fact-query-contract.md)

## Project semantics

Generic analyzers cannot infer every platform wrapper or trust boundary. C-GULL therefore allows project configuration to teach the analyzer about allocation/deallocation wrappers, banned functions, and semantic source/validator/sink/effect models.

See [Configuration](configuration.md) and [Trust-boundary semantic models](trust-boundary-semantic-models.md).
