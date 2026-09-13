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

## Initialize a project

From the root of a C project, create the recommended `.cgull.toml` configuration:

```bash
cgull init
```

On an interactive terminal, C-GULL offers three finding profiles:

- **Focused (recommended/default):** enables all security/correctness checks while explicitly skipping only `CGULL-019` and `CGULL-025`, the two opinionated low-severity policy checks;
- **Comprehensive:** enables every registered rule;
- **Custom:** shows each rule's ID, name, category, and severity and lets you select exclusions explicitly.

When stdin/stdout are not terminals, initialization never prompts and defaults to focused. Automation can choose explicitly:

```bash
cgull init --profile focused
cgull init --profile comprehensive
```

The generated file contains the actual `[rules].skip` entries and reasons; profiles are only an initialization convenience, not hidden persistent state. Existing include directories such as `include/`, `inc/`, and `src/include/` are detected, and an existing `compile_commands.json` is reported without copying all build-derived paths into TOML.

Existing `.cgullignore` and `.cgullincludes` users can migrate their settings without deleting the legacy files:

```bash
cgull init --migrate
```

Initialization refuses to overwrite or shadow an existing `.cgull.toml` or `pyproject.toml [tool.cgull]` configuration.

## First scan

From the root of a C project:

```bash
cgull scan .
```

Useful defaults are already selected. Scans remain read-only when no project configuration exists; `cgull init` is always explicit.

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

The canonical project fields are `[paths].exclude` for discovery exclusions, `[includes].roots` for include roots, `[scan]` for scan policy, plus `[output]`, `[rules]`, `[functions]`, and `[semantic_models]` for their existing purposes. For example:

```toml
schema_version = 1

[paths]
exclude = ["third_party/", "build/"]

[includes]
roots = ["include"]

[output]
fail_on = "high"
```

Then the normal command remains simple:

```bash
cgull scan .
```

See [Configuration](configuration.md) for the complete schema and precedence rules.

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
