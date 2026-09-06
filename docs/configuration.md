# Configuration reference

C-GULL supports project-wide TOML configuration in either a standalone `.cgull.toml` or a `[tool.cgull]` table in `pyproject.toml`. The same schema is used by both forms.

## Discovery and precedence

`cgull scan` searches upward from the primary scan target. At each directory it checks:

1. `.cgull.toml`;
2. `pyproject.toml` containing `[tool.cgull]`.

`.cgull.toml` therefore wins when both are present in the same directory. Pass `--config PATH` to select a file explicitly and bypass discovery.

Paths configured in the project file are interpreted in project/configuration context. Include roots are resolved relative to the directory containing the configuration file. `.cgullincludes` entries are resolved relative to the `.cgullincludes` file itself.

## Complete example

```toml
schema_version = 1
mode = "tu"

[rules]
skip = { "CGULL-019" = "Project coding standard does not require this rule" }

[rules.severity]
CGULL-024 = "high"
CGULL-020 = "low"

[functions.memory]
alloc = ["xmalloc", "kmalloc"]
realloc = ["xrealloc", "krealloc"]
dealloc = ["xfree", "kfree"]

[functions.banned.legacy_copy]
reason = "Unbounded project string-copy wrapper"
remediation = "Use safe_copy(dst, dst_size, src)"

[paths]
exclude = ["third_party/", "generated/"]
include_roots = ["include", "platform/include"]

[output]
default_format = "sarif"
fail_on = "high"
warn_on_fallback = true

[semantic_models]
# Project-specific source, validator, sink, ownership, or effect models.
# See trust-boundary-semantic-models.md for the model schema.
```

## `schema_version`

The current schema version is `1`. Use an integer:

```toml
schema_version = 1
```

Unknown top-level sections generate configuration warnings rather than being silently treated as supported settings.

## Scan mode

Translation-unit behavior can be selected at the top level:

```toml
mode = "tu"
```

or equivalently:

```toml
[scan]
mode = "tu"
```

Supported values are `file` and `tu`. A CLI `--mode` selection is intended for invocation-specific control. TU mode expands resolvable project headers and carries source provenance back to original files; see [Analysis model](analysis-model.md).

## Rules

### Disable rules

A mapping is preferred because it records the reason for the exception:

```toml
[rules]
skip = { "CGULL-019" = "Not part of this project's coding standard" }
```

A list is also accepted:

```toml
[rules]
skip = ["CGULL-019"]
```

Rule IDs are normalized to uppercase.

### Severity overrides

```toml
[rules.severity]
CGULL-024 = "high"
CGULL-020 = "low"
```

Valid configured rule severities are `high`, `medium`, `low`, and `info`.

## Function models

### Memory function synonyms

Teach memory-management rules about project/platform wrappers:

```toml
[functions.memory]
alloc = ["xmalloc", "kmalloc", "OPENSSL_malloc"]
realloc = ["xrealloc", "krealloc"]
dealloc = ["xfree", "kfree", "OPENSSL_free"]
```

Every entry must be a valid C identifier. These entries extend built-in function recognition rather than replacing it.

### Banned functions

Project-specific banned APIs can carry both rationale and remediation:

```toml
[functions.banned.legacy_string_copy]
reason = "Wrapper performs an unbounded copy"
remediation = "Use bounded_string_copy()"
```

A short string form is also accepted as the reason:

```toml
[functions.banned]
legacy_copy = "Legacy unbounded copy API"
```

Function keys must be valid C identifiers.

## Paths and includes

Exclude paths add to ignore behavior:

```toml
[paths]
exclude = ["third_party/", "generated/"]
```

Configure include search roots with either spelling:

```toml
[paths]
include_roots = ["include", "platform/include"]
```

or:

```toml
[includes]
roots = ["include", "platform/include"]
```

`[includes].include_roots` is also accepted. Include roots are ordered and resolved relative to the configuration directory. They are combined with roots loaded from `.cgullincludes`. See [Project files and suppressions](project-files.md).

## Output policy

```toml
[output]
default_format = "sarif"
fail_on = "high"
warn_on_fallback = true
```

`default_format` accepts `text`, `json`, `sarif`, or `markdown`. `fail_on` accepts `high`, `medium`, `low`, or `all`. `warn_on_fallback` accepts a TOML boolean; compatible `1/0` and common true/false strings are also parsed by the loader.

Use output policy for stable repository defaults and CLI switches for one-off overrides.

## Semantic models

`[semantic_models]` extends C-GULL's understanding of project-specific trust boundaries and call behavior. Unlike unknown cosmetic configuration, malformed semantic security models fail closed as configuration errors rather than being ignored.

See [Trust-boundary semantic models](trust-boundary-semantic-models.md) for the model contract and examples.

## Configuration-space inputs

Several analysis inputs are intentionally CLI concerns because they commonly vary by build:

```bash
cgull scan . --compile-commands build/compile_commands.json
cgull scan . --config-seed config/platform.h
cgull scan . --config-strategy pairwise
```

Available configuration expansion strategies are `baseline`, `one-at-a-time` (the CLI default), `pairwise`, and `exhaustive`. `--exhaustive-threshold` bounds exhaustive expansion. Use `cgull flags .` or `cgull scan . --list-flags` to inspect discovered conditional symbols.

For how these profiles affect analysis, see [Analysis model](analysis-model.md).
