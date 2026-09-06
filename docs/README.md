# C-GULL Documentation

This directory is the C-GULL knowledgebase. The repository root `README.md` is intentionally concise: it introduces C-GULL and gets a new user to a useful default scan quickly. Detailed operational, integration, and implementation material belongs here.

## User guide

| Topic | Document |
| --- | --- |
| Installation, first scan, and common CLI workflows | [Getting started](getting-started.md) |
| Complete project configuration reference | [Configuration](configuration.md) |
| `.cgullignore`, `.cgullincludes`, path boundaries, and inline suppressions | [Project files and suppressions](project-files.md) |
| Engines, file/TU modes, preprocessing, configuration profiles, and fallback behavior | [Analysis model](analysis-model.md) |
| Text, JSON, Markdown, SARIF, baselines, exit policy, and safe fixes | [Reporting and CI](reporting-and-ci.md) |
| pre-commit and GitHub Actions adoption | [Development integration](development-integration.md) |
| Rule inventory and identifiers | [Rule reference](rules.md) |
| Embedded-focused defaults and semantic trust boundaries | [Embedded security profile](embedded-security-profile.md) |

## Maintainer and extension guide

| Topic | Document |
| --- | --- |
| Repository architecture, adding rules, extending semantic models, tests, and benchmarks | [Repository extension](repository-extension.md) |
| Interprocedural architecture | [Interprocedural analysis](interprocedural-analysis.md) |
| Interprocedural fact/query contract | [Interprocedural fact query contract](interprocedural-fact-query-contract.md) |
| Trust-boundary semantic models | [Trust-boundary semantic models](trust-boundary-semantic-models.md) |
| Historical interprocedural work plan | [Interprocedural analysis issues](interprocedural-analysis-issues.md) |

## Documentation conventions

User-facing documentation should describe released behavior and defaults rather than implementation aspirations. Commands should be copy/pasteable. Configuration examples should identify whether paths are relative to the configuration file, scan target, or another file. Maintainer design notes should link back to the stable user-facing contract when one exists.
