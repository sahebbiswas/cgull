# Project files and suppressions

C-GULL uses small repository-local files for scan boundaries and include resolution. Keep these files in version control when they define team-wide analysis behavior.

## `.cgullignore`

`.cgullignore` excludes paths from discovery. It is appropriate for third-party code, generated files, build trees, fixtures, or other content that is not part of the analysis boundary.

Generate a starter file with:

```bash
cgull init-ignore
```

Patterns use gitignore-style matching, including negation. A typical file is:

```gitignore
# Build output
build/
out/

# Vendored code
third_party/
vendor/

# Generated sources
generated/

# Re-include a project-owned adapter inside an otherwise ignored tree
!vendor/project_adapter.c
```

You can select another file for an invocation:

```bash
cgull scan . --ignore-file config/security.ignore
```

or add ad-hoc patterns without editing the file:

```bash
cgull scan . --ignore-pattern 'generated/**' --ignore-pattern 'vendor/**'
```

`[paths].exclude` in `.cgull.toml` is additive with ignore patterns. Prefer `.cgullignore` for a readable path-boundary list and TOML exclusions when the exclusion is tightly coupled to other C-GULL project policy.

## `.cgullincludes`

`.cgullincludes` supplies ordered include search roots for translation-unit expansion. The format is intentionally simple: one directory per line, blank lines ignored, `#` starts a comment.

```text
# Project headers
include
platform/include
../shared/include
```

Relative entries are resolved relative to the directory containing `.cgullincludes`. Duplicate resolved roots are ignored while preserving search order.

Equivalent roots can be declared in `.cgull.toml`:

```toml
[includes]
roots = ["include", "platform/include"]
```

The TOML roots and `.cgullincludes` roots are combined.

### Include lookup behavior

For `#include "header.h"`, C-GULL checks the including source directory first, then configured include roots in order. For `#include <header.h>`, it searches configured include roots.

The resolver constrains resolved files to trusted project/source/include roots by default. This containment prevents path traversal or symlink resolution from silently expanding the analysis boundary. Unresolved system headers do not make the scanner unsafe; analysis can continue with the available source context.

## `.cgull.toml`

The project configuration file controls rule policy, severity, function/semantic models, paths, includes, scan mode, and output policy. See the dedicated [Configuration reference](configuration.md).

C-GULL also accepts the same configuration under `[tool.cgull]` in `pyproject.toml`.

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

| Need | Mechanism |
| --- | --- |
| Ignore an entire vendor/generated path | `.cgullignore` |
| Add project header roots | `.cgullincludes` or TOML include roots |
| Change rule/project policy | `.cgull.toml` / `[tool.cgull]` |
| Accept existing findings while blocking new ones | baseline JSON |
| Suppress one intentional source occurrence | inline rule-specific suppression |
| Temporarily exclude a path for one invocation | `--ignore-pattern` / `--ignore-file` |
