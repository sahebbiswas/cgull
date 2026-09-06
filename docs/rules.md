# Rule reference

C-GULL rule identifiers are stable diagnostic identities. Use the CLI as the authoritative installed-version catalog:

```bash
cgull rules
```

The command reports each active rule's ID, name, impact, category, CWE mapping, implementation method, and analysis engine from the same metadata used by the scanner. This avoids a manually duplicated table drifting behind the code as rules evolve.

## Rule families

The current registry covers security and correctness concerns including:

- banned/dangerous APIs and unsafe conversions;
- format strings and command injection;
- dynamic allocation, nullness, ownership, leaks, double free, use-after-free, and stack lifetime;
- array bounds, pointer arithmetic, integer arithmetic, signedness, VLAs, and object sizing;
- cryptographic/sensitive-memory and timing patterns;
- TOCTOU and selected environment/sandbox checks;
- external-data trust boundaries;
- control-flow, dead/unused code, inclusion guards, and selected MISRA/style checks.

Rule implementations live under `cgull/rules/` and are registered in `cgull/rules/__init__.py`.

## Configuration by rule ID

Disable a rule with a recorded justification:

```toml
[rules]
skip = { "CGULL-019" = "Not required by this project's coding standard" }
```

Override severity:

```toml
[rules.severity]
CGULL-024 = "high"
```

Suppress a single intentional occurrence in source:

```c
legacy_call(); // cgull-ignore: CGULL-001
```

See [Configuration](configuration.md) and [Project files and suppressions](project-files.md).

## CWE mappings and benchmark credit

A rule's CWE metadata describes the weakness class it is intended to identify. Benchmark mappings are maintained separately so detection-quality accounting can credit every applicable signal without conflating a CWE mapping with demonstrated recall.

For contributor guidance on adding or changing rules, see [Repository extension](repository-extension.md).
