# Development integration

This guide covers integrating C-GULL into the software-development lifecycle. For extending C-GULL itself, see [Repository extension](repository-extension.md).

## Local developer workflow

Keep the common path short:

```bash
cgull scan .
```

Put stable team policy in `.cgull.toml`, `.cgullignore`, and `.cgullincludes` rather than requiring every developer to remember a long command line. Use CLI switches for investigation and one-off overrides.

Before adopting a hard gate, tune project semantics and establish a baseline if necessary. See [Configuration](configuration.md) and [Reporting and CI](reporting-and-ci.md).

## pre-commit

C-GULL publishes a pre-commit hook. Pin a released tag rather than a moving branch:

```yaml
repos:
  - repo: https://github.com/sahebbiswas/cgull
    rev: <released-tag>
    hooks:
      - id: cgull
```

The repository hook runs C-GULL against staged supported source files. Keep pre-commit checks reasonably fast; use broader configuration-space scans in CI when they are too expensive for every commit.

## GitHub Actions

C-GULL includes a composite action. A minimal security scan can be integrated as:

```yaml
name: C-GULL

on:
  pull_request:
  push:
    branches: [main]

jobs:
  cgull:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v7

      - uses: sahebbiswas/cgull@<released-tag>
        with:
          path: .
          fail-on: high
          upload-sarif: true
```

Pin `<released-tag>` to the version your project has validated.

### Composite action inputs

The action exposes the common CI surface:

| Input | Purpose | Default |
| --- | --- | --- |
| `path` | source file/directory target | `.` |
| `severity` | report severity filter | `all` |
| `fail-on` | failure threshold | `high` |
| `format` | report format | `sarif` |
| `sarif-file` | SARIF output path | `results.sarif` |
| `upload-sarif` | upload SARIF to GitHub Code Scanning | `false` |

For advanced CLI options not exposed by the composite action, install C-GULL in the workflow and invoke `cgull scan` directly.

## Baseline-based pull-request gating

For an existing repository:

```bash
cgull scan . --update-baseline .cgull-baseline.json
```

Review and commit that baseline. CI can then enforce:

```bash
cgull scan . --baseline .cgull-baseline.json --fail-on high --fail-on-error
```

This makes the security ratchet explicit: accepted historical findings remain visible as debt while new findings can block a change.

## Build-aware analysis

For projects with significant conditional compilation, provide build information rather than relying only on generic source discovery:

```bash
cgull scan . --compile-commands build/compile_commands.json --mode tu
```

You can supplement this with configuration seeds and controlled configuration-space expansion. Keep the chosen strategy stable in CI so metrics and baselines remain comparable.

## SARIF as an integration boundary

SARIF is the preferred interchange when a hosting or security platform understands it:

```bash
cgull scan . --format sarif -o results.sarif --fail-on high
```

Treat report publication and build failure as independent concerns: publishing SARIF preserves diagnostic visibility, while `--fail-on` expresses repository policy.

## Repository policy recommendations

For a production utility workflow:

- commit `.cgull.toml`, `.cgullignore`, and `.cgullincludes` when they encode shared policy;
- pin C-GULL versions in automation;
- keep local defaults fast enough for routine use;
- use CI for broader TU/configuration-space coverage;
- require justification for project-wide skipped rules and prefer narrow source suppressions;
- treat baseline changes as reviewable security-policy changes;
- archive JSON/SARIF reports when longitudinal metrics matter.
