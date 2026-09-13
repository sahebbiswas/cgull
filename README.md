# C-GULL

**Code Guardian for Unchecked Logic & Leaks** — static security analysis for C codebases.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](https://github.com/sahebbiswas/cgull/blob/main/LICENSE)
[![Security Standards](https://img.shields.io/badge/standards-MISRA--C%20%7C%20CWE%20%7C%20CERT--C-orange.svg)](https://cwe.mitre.org/)
[![Tests](https://github.com/sahebbiswas/cgull/actions/workflows/ci.yml/badge.svg)](https://github.com/sahebbiswas/cgull/actions/workflows/ci.yml)

C-GULL is a Python-based static analyzer focused on security, memory safety, correctness, and defensive C development. It combines lightweight pattern analysis with structural parsing, control/data-flow analysis, and interprocedural facts, while remaining usable as a simple command-line utility.

It is designed for incremental adoption: run it with useful defaults on an existing source tree, then add project-specific include paths, wrappers, trust-boundary models, baselines, and CI policy as needed.

## Why C-GULL

- **Security-oriented C analysis** — memory lifetime, unsafe APIs, bounds/arithmetic, format strings, command injection, trust boundaries, sensitive data, and selected compliance/correctness checks.
- **Hybrid analysis** — regex, AST/structural, CFG/data-flow, and interprocedural analysis are used where appropriate.
- **Build-aware operation** — translation-unit mode, include resolution, compile-command ingestion, and conditional-configuration exploration support real C projects.
- **Project semantics** — model custom allocators, deallocators, banned wrappers, sources, validators, sinks, and call effects without hardcoding project names into rules.
- **CI-ready reporting** — terminal, JSON, Markdown, and SARIF output; severity gates, analysis-error/fallback gates, and baseline/diff adoption.
- **Conservative automation** — findings distinguish mechanically safe fixes from suggested fixes and manual review.

## Install

C-GULL requires Python 3.10+.

```bash
python -m pip install cgull
```

Install optional AST/preprocessing support for the strongest structural analysis:

```bash
python -m pip install "cgull[ast]"
```

## Get started

From the root of a C project, initialize one editable project configuration:

```bash
cgull init
```

Interactive terminals offer focused, comprehensive, and custom finding profiles. In scripts/CI, initialization is deterministic and defaults to the focused profile; use `--profile comprehensive` when every registered rule should remain enabled. The focused profile keeps security/correctness coverage while explicitly skipping only the opinionated low-severity `CGULL-019` and `CGULL-025` policy checks.

Then scan the project:

```bash
cgull scan .
```

C-GULL also works without project configuration: scans remain read-only and use inferred defaults when `.cgull.toml` is absent.

Scan a narrower target when needed:

```bash
cgull scan src/
cgull scan src/main.c include/project.h
```

List the installed rule catalog:

```bash
cgull rules
```

## Add project policy

`.cgull.toml` is the recommended project configuration surface. C-GULL automatically discovers it, or `[tool.cgull]` in `pyproject.toml`, by searching upward from the scan target. For example:

```toml
schema_version = 1

[paths]
exclude = ["third_party/", "build/"]

[includes]
roots = ["include"]

[output]
fail_on = "high"
```

The everyday command remains:

```bash
cgull scan .
```

Existing `.cgullignore` and `.cgullincludes` files continue to load for compatibility. New projects should keep scan boundaries and include roots in `.cgull.toml`; migrate an existing project with `cgull init --migrate` and review the generated TOML before removing legacy files.

## Common workflows

Generate machine-readable reports:

```bash
cgull scan . --format json -o cgull.json
cgull scan . --format sarif -o cgull.sarif
```

Gate high-severity findings in CI:

```bash
cgull scan . --fail-on high
```

Adopt C-GULL on a codebase with existing findings:

```bash
cgull scan . --update-baseline .cgull-baseline.json
cgull scan . --baseline .cgull-baseline.json --fail-on high
```

Use translation-unit/build context:

```bash
cgull scan . --mode tu --compile-commands build/compile_commands.json
```

Preview or apply mechanically safe fixes:

```bash
cgull scan . --fix
cgull scan . --fix --write
```

## Documentation

The [documentation knowledgebase](https://github.com/sahebbiswas/cgull/blob/main/docs/README.md) contains the detailed user and maintainer guides. Start with:

- [Getting started](https://github.com/sahebbiswas/cgull/blob/main/docs/getting-started.md) — installation, initialization, defaults, first scan, and adoption path.
- [Configuration reference](https://github.com/sahebbiswas/cgull/blob/main/docs/configuration.md) — `.cgull.toml`, `pyproject.toml`, rules, functions, paths, output policy, and semantic models.
- [Project files and suppressions](https://github.com/sahebbiswas/cgull/blob/main/docs/project-files.md) — canonical project configuration, legacy migration, baselines, include boundaries, and inline suppression.
- [Analysis model](https://github.com/sahebbiswas/cgull/blob/main/docs/analysis-model.md) — engines, TU mode, parser tiers, configuration profiles, and interprocedural analysis.
- [Reporting and CI](https://github.com/sahebbiswas/cgull/blob/main/docs/reporting-and-ci.md) — report formats, failure policy, baselines, fixes, and CI adoption.
- [Development integration](https://github.com/sahebbiswas/cgull/blob/main/docs/development-integration.md) — pre-commit, GitHub Actions, SARIF, and build-aware integration.
- [Rule reference](https://github.com/sahebbiswas/cgull/blob/main/docs/rules.md) — rule catalog conventions and configuration by stable rule ID.
- [Repository extension](https://github.com/sahebbiswas/cgull/blob/main/docs/repository-extension.md) — architecture and guidance for contributors extending C-GULL.
- [Embedded security profile](https://github.com/sahebbiswas/cgull/blob/main/docs/embedded-security-profile.md) — embedded-focused security defaults and guidance.

For changes between releases, see the [changelog](https://github.com/sahebbiswas/cgull/blob/main/CHANGELOG.md). [GitHub Releases](https://github.com/sahebbiswas/cgull/releases) contain release-specific summaries and generated pull-request lists. Maintainers should follow the [release guide](https://github.com/sahebbiswas/cgull/blob/main/docs/releasing.md); contributors should also read [CONTRIBUTING.md](https://github.com/sahebbiswas/cgull/blob/main/CONTRIBUTING.md).

## Project status

C-GULL is under active development. Static analysis is necessarily conservative and no analyzer proves that C code is secure. Treat findings as engineering evidence: review them in source/build context, tune project semantics deliberately, and combine static analysis with compiler diagnostics, testing, sanitizers, fuzzing, review, and platform-specific security controls.

## License

C-GULL is licensed under the [Apache License 2.0](https://github.com/sahebbiswas/cgull/blob/main/LICENSE).
