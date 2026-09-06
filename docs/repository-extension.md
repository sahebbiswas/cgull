# Repository extension

This document is for contributors extending C-GULL itself: adding rules, analysis facts, configuration surfaces, reports, or benchmark coverage. For integrating C-GULL into another repository, see [Development integration](development-integration.md).

## Architecture at a glance

The repository is intentionally layered:

- `cgull/cli.py` and `cgull/cli_base.py` — command-line contract and invocation policy;
- `cgull/config.py` — project configuration discovery, validation, and rule configuration;
- `cgull/engine.py` — scan orchestration;
- `cgull/rules/` — rule implementations and registry;
- `cgull/ast_analyzer/` — preprocessing, parsing, configuration profiles, types, and structural traversal;
- `cgull/cfg/` — control-flow/data-flow models and interprocedural summaries/facts;
- `cgull/analysis_session.py` — shared per-analysis caching/query ownership;
- `cgull/semantic_models.py` — declarative project semantics;
- `cgull/includes.py` — include resolution and TU expansion;
- `cgull/reporter.py` / SARIF support — output contracts;
- `benchmarks/` — quality/performance/release evidence;
- `tests/` — unit and regression contracts;
- `docs/` — user and maintainer knowledgebase.

Preserve these boundaries when adding functionality. A rule should consume shared analysis services rather than rebuilding its own parser, call graph, predecessor map, or interprocedural fixed point.

## Adding a rule

Rules derive from `BaseRule`. A rule declares stable metadata such as `rule_id`, name, severity, category, CWE, remediation, and intended analysis engine, then implements the appropriate scan surface.

Lightweight rules can override `scan_line(...)`. Structural/data-flow rules normally override `scan_ast(...)`. AST rules can obtain the shared lazy analysis session with:

```python
session = self.get_analysis_session(ast_ctx)
```

Use `create_issue(...)` so findings consistently carry rule metadata, source position, remediation, and fix classification.

After implementing a rule:

1. register the class in `cgull/rules/__init__.py` and `ALL_RULES`;
2. give it a stable, non-reused `CGULL-xxx` identifier;
3. add focused positive and negative unit tests;
4. add regression fixtures for known false positives/edge cases;
5. map benchmark CWE credit only when the rule genuinely detects that weakness class;
6. update user-facing rule documentation;
7. update the patch version when the repository's release process requires it.

## Fix classifications

Use the narrowest safe fix contract:

- `SAFE_FIX` only when the replacement is mechanically safe to apply;
- `SUGGESTED_FIX` when the analyzer can propose code but developer judgment is required;
- `MANUAL_REVIEW` when no reliable replacement should be generated.

Do not turn a plausible remediation into an automatic edit merely because a replacement string is easy to construct.

## Reuse shared analysis

Interprocedural and CFG work is deliberately centralized. Before adding rule-local graph traversal or repeated fixed-point computation, inspect `cgull/cfg/`, `analysis_session.py`, and the fact-query contract.

The design goal is that expensive TU facts are computed once and consumed by multiple rules. New fact domains should have explicit lattice/merge semantics, deterministic iteration, conservative unknown behavior, and tests for recursive/cyclic call graphs.

See [Interprocedural fact query contract](interprocedural-fact-query-contract.md).

## Extending semantic models

Platform-specific function behavior belongs in declarative semantic models when possible rather than hardcoded rule conditionals. This keeps generic rules reusable across embedded, libc, kernel, and project-wrapper environments.

Changes to the semantic model schema must:

- validate strictly;
- fail closed for malformed security-critical models;
- preserve existing configuration compatibility where practical;
- include configuration parser tests and rule-level behavioral tests;
- update [Configuration](configuration.md) and [Trust-boundary semantic models](trust-boundary-semantic-models.md).

## Extending configuration

Add new project settings through `CGullConfig` and `load_config()`. Document precedence and path-resolution semantics explicitly. Unknown/malformed values must not silently change security behavior.

If a setting is stable team policy, prefer a TOML surface. If it is naturally build/invocation-specific, a CLI input may be more appropriate. Avoid adding two equivalent controls without defining precedence.

## Tests and quality evidence

A rule change should normally include both correctness tests and detection-quality evidence appropriate to its scope. C-GULL's benchmark layer exists to prevent a growing rule count from being mistaken for improving detection quality.

Use:

- focused unit tests for transfer/query behavior;
- regression tests for previously observed failures;
- representative corpus/Juliet measurements for detection changes;
- deterministic repeated runs where output ordering or fixed points matter;
- release/performance gates for changes to shared analysis infrastructure.

Do not weaken a benchmark budget simply to accommodate an unexplained regression.

## Documentation changes

The root README is a product entry point, not a complete manual. Put detailed behavior in a feature-scoped document under `docs/` and link it from `docs/README.md`. Keep examples synchronized with the CLI/config parser rather than documenting aspirational flags.

## Compatibility expectations

C-GULL is approaching a stable utility contract. Treat the following as compatibility-sensitive:

- rule IDs and their semantic meaning;
- CLI commands/options and exit behavior;
- configuration keys and precedence;
- JSON/SARIF schema semantics;
- baseline fingerprint behavior;
- public imports intentionally retained by package initializers;
- semantic-model configuration.

Prefer additive evolution and explicit deprecation over silent contract changes.
