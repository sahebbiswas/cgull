# C-GULL

**Code Guardian for Unchecked Logic & Leaks** — static security analysis for C codebases.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
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

From the root of a C project:

```bash
cgull scan .
```

That is the intended default workflow. C-GULL recursively discovers supported source/header files, uses the `hybrid` engine, reports all severities, runs sequentially, and writes a terminal report.

Scan a narrower target when needed:

```bash
cgull scan src/
cgull scan src/main.c include/project.h
```

List the installed rule catalog:

```bash
cgull rules
```

Create a starter ignore file:

```bash
cgull init-ignore
```

## Add project policy

C-GULL automatically discovers `.cgull.toml`, or `[tool.cgull]` in `pyproject.toml`, by searching upward from the scan target. For example:

```toml
schema_version = 1

[paths]
exclude = ["third_party/", "build/"]

[output]
fail_on = "high"
```

The everyday command remains:

```bash
cgull scan .
```

Project include roots can be kept in `.cgullincludes`, while `.cgullignore` defines files/directories outside the scan boundary. See the documentation links below for their exact resolution and precedence behavior.

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

The [`docs/`](docs/README.md) directory is the C-GULL knowledgebase. Start with:

- [Getting started](docs/getting-started.md) — installation, defaults, first scan, and adoption path.
- [Configuration reference](docs/configuration.md) — `.cgull.toml`, `pyproject.toml`, rules, functions, paths, output policy, and semantic models.
- [Project files and suppressions](docs/project-files.md) — `.cgullignore`, `.cgullincludes`, baselines, include boundaries, and inline suppression.
- [Analysis model](docs/analysis-model.md) — engines, TU mode, parser tiers, configuration profiles, and interprocedural analysis.
- [Reporting and CI](docs/reporting-and-ci.md) — report formats, failure policy, baselines, fixes, and CI adoption.
- [Development integration](docs/development-integration.md) — pre-commit, GitHub Actions, SARIF, and build-aware integration.
- [Rule reference](docs/rules.md) — rule catalog conventions and configuration by stable rule ID.
- [Repository extension](docs/repository-extension.md) — architecture and guidance for contributors extending C-GULL.
- [Embedded security profile](docs/embedded-security-profile.md) — embedded-focused security defaults and guidance.

For changes between releases, see [CHANGELOG.md](CHANGELOG.md) and [RELEASE_NOTES.md](RELEASE_NOTES.md). Contributors should also read [CONTRIBUTING.md](CONTRIBUTING.md).

## Project status

C-GULL is under active development. Static analysis is necessarily conservative and no analyzer proves that C code is secure. Treat findings as engineering evidence: review them in source/build context, tune project semantics deliberately, and combine static analysis with compiler diagnostics, testing, sanitizers, fuzzing, review, and platform-specific security controls.

## License

C-GULL is licensed under the [Apache License 2.0](LICENSE).
