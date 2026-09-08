# Compilation database build context

C-GULL can consume a Clang-style `compile_commands.json` both for preprocessor macro seeds and for translation-unit include search paths. This lets translation-unit expansion see project headers that are reachable only through the real build command instead of requiring those paths to be duplicated in `.cgullincludes`.

```bash
cgull scan . --mode tu --compile-commands build/compile_commands.json
```

When `--compile-commands` is omitted, the existing compilation-database discovery rules still apply. Macro parsing for `-D` and `-U` is unchanged; include-path extraction is a separate build-context layer.

## Supported include options

C-GULL derives ordered include roots from each compilation-database entry independently. Both `arguments` arrays and shell-style `command` strings are supported.

Supported forms are:

- `-Ipath`
- `-I path`
- `-isystem path`
- attached `-isystempath` / `-isystem=path` forms when present

Relative include paths are resolved against that entry's `directory`, as required by compilation-database semantics. They are never resolved against the process working directory. Canonically equivalent roots are deduplicated while preserving the first effective occurrence.

Ordinary `-I` roots are searched before `-isystem` roots, preserving compiler-style include-class ordering and the original order inside each class.

## Per-translation-unit isolation

Include roots from a compilation-database entry apply only to the source file named by that entry. C-GULL does not merge all compilation-database include paths into a process-wide list. This matters when two translation units use different generated headers, SDKs, feature directories, or include ordering.

If the database contains multiple entries for the same source file with different include roots, C-GULL uses the first entry deterministically and emits a warning rather than merging incompatible build contexts.

## Precedence with explicit C-GULL include roots

Explicit C-GULL project configuration has higher precedence than build-derived roots. For each translation unit, the effective search order is:

1. the including source file's local directory for quote includes, as before;
2. explicit roots from `.cgull.toml` / `pyproject.toml` and `.cgullincludes`, in their existing order;
3. that translation unit's `-I` roots from `compile_commands.json`;
4. that translation unit's `-isystem` roots.

This policy keeps explicit user configuration authoritative while allowing the compilation database to supply missing build context. Canonical duplicates are removed without reordering distinct roots.

## Unsupported include-affecting flags

C-GULL does not silently approximate compiler options whose search semantics it cannot currently reproduce. Unsupported include-affecting flags are ignored with a warning. This currently includes quote-only `-iquote`, sysroot controls, `-nostdinc`, `-idirafter`, prefix-based include options, and framework search options.

`-iquote` is deliberately not treated as `-I`: doing so would incorrectly expose a quote-only directory to angle includes. Full quote/system/sysroot emulation can be added later without changing the deterministic behavior documented here.

## Why this improves analysis

Header resolution feeds the shared translation-unit AST pipeline. Recovering a header through the compilation database can therefore restore typedefs, prototypes, macros, declarations, and other semantic context used by multiple rules. For example, a declaration-only function prototype found only through a build include root can make argument-conversion analysis resolvable instead of unknown.
