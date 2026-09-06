# Getting started

C-GULL is a static security analyzer for C projects. The default CLI is deliberately usable without project configuration: point `cgull scan` at a source tree and the hybrid analyzer recursively discovers supported C source/header files and reports findings to the terminal.

## Requirements and installation

C-GULL requires Python 3.10 or newer.

Install the package from PyPI:

```bash
python -m pip install cgull
```

For the strongest AST-assisted analysis, install the optional AST dependencies:

```bash
python -m pip install "cgull[ast]"
```

For repository development:

```bash
git clone https://github.com/sahebbiswas/cgull.git
cd cgull
python -m pip install -e ".[ast]"
```

## First scan

From the root of a C project:

```bash
cgull scan .
```

Useful defaults are already selected:

- target: current directory when none is supplied;
- engine: `hybrid`;
- severity filter: `all`;
- scan mode: per-file unless project/CLI configuration selects TU mode;
- parallelism: one in-process worker;
- report: terminal text to stdout unless project configuration selects another default.

Scan a narrower target when appropriate:

```bash
cgull scan src/
cgull scan src/main.c include/project.h
```

## Understand the result

C-GULL findings carry stable `CGULL-xxx` rule identifiers, severity, source location, CWE/compliance metadata where applicable, and remediation information. List the active rule catalog with:

```bash
cgull rules
```

The analyzer may use regex, AST/structural, CFG/data-flow, and interprocedural facts depending on the rule and available source context. See [Analysis model](analysis-model.md) before using parser fallback as a quality gate.

## Add project defaults

C-GULL automatically searches upward from the scan target for `.cgull.toml`, or for `[tool.cgull]` in `pyproject.toml`. A standalone `.cgull.toml` takes precedence when both exist in the same directory.

A small starting configuration is:

```toml
schema_version = 1

[paths]
exclude = ["third_party/", "build/"]

[output]
fail_on = "high"
```

Then the normal command remains simple:

```bash
cgull scan .
```

See [Configuration](configuration.md) for the complete schema and precedence rules.

## Exclude non-project code

Create a starter `.cgullignore`:

```bash
cgull init-ignore
```

Use it for vendor code, generated output, test fixtures, or other paths that should not be scanned. See [Project files and suppressions](project-files.md).

## CI-friendly scan

To fail when a high-severity finding is present:

```bash
cgull scan . --fail-on high
```

For an established codebase, baseline the current findings and gate only new findings:

```bash
cgull scan . --update-baseline .cgull-baseline.json
cgull scan . --baseline .cgull-baseline.json --fail-on high
```

For machine ingestion:

```bash
cgull scan . --format json -o cgull.json
cgull scan . --format sarif -o cgull.sarif
```

See [Reporting and CI](reporting-and-ci.md) and [Development integration](development-integration.md) for production adoption patterns.

## Next steps

- [Configuration reference](configuration.md)
- [Project files and suppressions](project-files.md)
- [Analysis model](analysis-model.md)
- [Reporting and CI](reporting-and-ci.md)
- [Rule reference](rules.md)
