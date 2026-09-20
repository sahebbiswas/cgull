# Persistent result cache

C-GULL can optionally reuse finalized per-file analysis results across process
invocations when the analysis inputs are unchanged. This is distinct from the
in-process TU/header and CFG caches, which only live for a single scan.

The first slice is **opt-in**, content-addressed, and conservative about
invalidation. Prefer correctness over hit rate.

## Enabling

```bash
# Default location: <project>/.cgull/cache (gitignored via .cgull/)
cgull scan . --cache-dir

# Explicit directory (useful for CI cache actions)
cgull scan . --cache-dir "$RUNNER_TEMP/cgull-cache"

# Environment equivalent
export CGULL_CACHE_DIR=.cgull/cache
cgull scan .
```

Disable even when a directory is configured:

```bash
cgull scan . --cache-dir --no-cache
# or
CGULL_NO_CACHE=1 cgull scan . --cache-dir
```

When no project root is available, the default falls back to
`$XDG_CACHE_HOME/cgull` or `~/.cache/cgull`.

## Cache identity

Each entry is keyed by a digest of:

- source file bytes;
- fully expanded translation-unit text (so included headers participate);
- scan configuration fingerprint (engine, mode, enabled rules, macros,
  include roots, suppressions, and related `ScanConfig` fields);
- a digest of rule-attached semantic/call-effect models;
- C-GULL package version;
- cache schema version (`1`).

Changing any of those inputs yields a miss and recomputes the file.

## What is stored

JSON records of finalized findings plus parser/status metadata needed to rebuild
the same per-file scan tuple. Live AST objects, locks, and `AnalysisSession`
state are never persisted.

## Current limitations

- Entries that depend on **cross-TU project summaries** are not cached in this
  slice (the prepared AST context carries those summaries, and they are not yet
  part of the key). Single-file and non-summary scans benefit today.
- Cache size/eviction is user-managed for v1 (delete the cache directory).
- Multi-process writers use atomic `os.replace`; a corrupt file becomes a miss.

## Verification tips

Warm-cache behavior can be checked by scanning twice with the same `--cache-dir`
and confirming the second run finishes much faster on an unchanged tree while
producing the same findings/fingerprints. Injecting a truncated JSON file under
the cache directory should force a miss rather than a scan failure.
