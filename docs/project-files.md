# Project files and suppressions

`.cgull.toml` is the single recommended project setup surface for new C-GULL projects. Keep it in version control when it defines team-wide scan boundaries, include roots, rule policy, and output behavior.

Create it with:

```bash
cgull init
```

The initializer uses canonical fields such as `[paths].exclude` and `[includes].roots`, detects common include directories that actually exist, and writes explicit rule skips rather than persisting opaque profile names.

## `.cgull.toml`

The project configuration file controls rule policy, severity, function/semantic models, paths, includes, scan mode, and output policy. See the dedicated [Configuration reference](configuration.md).

C-GULL also accepts the same configuration under `[tool.cgull]` in `pyproject.toml`. `cgull init` refuses to create a `.cgull.toml` that would overwrite or shadow either form.

A typical generated configuration uses:

```toml
schema_version = 1

[paths]
exclude = ["build/", "dist/", "vendor/", "third_party/"]

[includes]
roots = ["include"]

[output]
default_format = "text"
warn_on_fallback = false

[rules]
skip = {
    "CGULL-019" = "Focused profile: explicit void style is project policy",
    "CGULL-025" = "Focused profile: assertion placement is project policy",
}
```

Only detected include roots are activated. Scan mode is omitted by default so target-sensitive CLI mode inference can remain effective.

## Legacy `.cgullignore`

`.cgullignore` remains a supported compatibility input for discovery exclusions. Patterns use gitignore-style matching, including negation. Existing projects do not need to migrate immediately.

For new configuration, prefer `[paths].exclude` in `.cgull.toml`. To import an existing file while preserving ordering and negated patterns:

```bash
cgull init --migrate
```

The migration does not delete or modify `.cgullignore`; review the generated TOML before removing the legacy file.

You can still select another ignore file for one invocation:

```bash
cgull scan . --ignore-file config/security.ignore
```

or add ad-hoc patterns without editing project configuration:

```bash
cgull scan . --ignore-pattern 'generated/**' --ignore-pattern 'vendor/**'
```

## Legacy `.cgullincludes`

`.cgullincludes` remains a supported compatibility input for ordered include search roots. Its format is one directory per line, with blank lines ignored and `#` introducing comments.

```text
include
platform/include
../shared/include
```

For new configuration, prefer the canonical TOML form:

```toml
[includes]
roots = ["include", "platform/include"]
```

`cgull init --migrate` imports legacy roots into `[includes].roots`, normalizes relative path separators, preserves ordering, and leaves the source file untouched.

### Include lookup behavior

For `#include "header.h"`, C-GULL checks the including source directory first, then configured include roots in order. For `#include <header.h>`, it searches configured include roots.

The resolver constrains resolved files to trusted project/source/include roots by default. This containment prevents path traversal or symlink resolution from silently expanding the analysis boundary. Unresolved system headers do not make the scanner unsafe; analysis can continue with the available source context.

## Baseline files

A baseline is an ordinary C-GULL JSON report used to distinguish existing findings from new ones:

```bash
cgull scan . --update-baseline .cgull-baseline.json
cgull scan . --baseline .cgull-baseline.json --fail-on high
```

For team adoption, commit the baseline when it represents an explicitly accepted migration state. Refresh it intentionally rather than automatically hiding new findings. See [Reporting and CI](reporting-and-ci.md).

## Inline suppressions

Use source suppressions for a narrow, reviewed exception where excluding a whole file or disabling a rule project-wide would be too broad.

```c
strcpy(dest, src); // cgull-ignore: CGULL-001

// cgull-disable-next-line CGULL-007
value = array[index];

/* cgull-disable-line CGULL-019 */
int helper(void) { return 0; }

// cgull-ignore-next-line: CGULL-001,CGULL-003
legacy_call();
```

A bare `cgull-ignore` suppresses all C-GULL findings on that line. Prefer rule-specific suppression where possible: it documents the intended exception without masking unrelated future diagnostics.

## Choosing the right mechanism

| Need | Recommended mechanism |
| --- | --- |
| Initialize project policy | `cgull init` -> `.cgull.toml` |
| Ignore vendor/generated paths | `[paths].exclude` |
| Add project header roots | `[includes].roots` |
| Change rule/project policy | `[rules]`, `[functions]`, `[semantic_models]` |
| Migrate legacy project files | `cgull init --migrate` |
| Accept existing findings while blocking new ones | baseline JSON |
| Suppress one intentional source occurrence | inline rule-specific suppression |
| Temporarily exclude a path for one invocation | `--ignore-pattern` / `--ignore-file` |

Legacy `.cgullignore` and `.cgullincludes` files continue to load for backward compatibility, but they are no longer presented as equal first-time setup choices.