# Reporting and CI

C-GULL can serve an interactive developer workflow and a machine-enforced CI policy without requiring different analyzers. Keep the scan inputs stable, then choose the report and exit policy appropriate to the consumer.

## Report formats

```bash
cgull scan . --format text
cgull scan . --format json -o cgull.json
cgull scan . --format markdown -o cgull.md
cgull scan . --format sarif -o cgull.sarif
```

- `text` is the normal terminal experience;
- `json` is the stable machine-oriented report and baseline source;
- `markdown` is useful for human review and CI artifacts;
- `sarif` integrates with SARIF consumers such as code-scanning platforms.

A project can set `[output].default_format` in `.cgull.toml`.

## Severity filtering versus failure policy

`--severity` controls which severities are included in the scan result. `--fail-on` controls when findings cause a non-zero policy result. Keep those concepts separate.

```bash
# Report everything, fail the build for high-severity findings.
cgull scan . --severity all --fail-on high
```

Supported failure thresholds are `high`, `medium`, `low`, and `all`. `--fail-on-high` remains a compatibility alias for `--fail-on high`.

Use `--fail-on-error` when file-analysis failures must also fail CI, and `--warn-on-fallback` when structural parser fallback is unacceptable for the repository.

## Baseline / diff adoption

A baseline lets a mature codebase adopt C-GULL without pretending existing debt can be fixed immediately.

Create a baseline:

```bash
cgull scan . --update-baseline .cgull-baseline.json
```

Then report/count only findings that are new relative to it:

```bash
cgull scan . --baseline .cgull-baseline.json --fail-on high
```

The baseline is an ordinary C-GULL JSON report. Matching uses a content-oriented finding fingerprint rather than relying only on line numbers, so unrelated line movement does not automatically turn an unchanged finding into a new one.

Use equivalent scan inputs when creating and consuming a baseline. Changing severity, engine, configuration profiles, or analysis boundaries can make findings appear added/resolved because the analyzed universe changed.

A committed baseline should be treated as reviewed security debt. Update it deliberately after remediation or an explicit policy decision; do not refresh it automatically merely to make CI green.

## Safe fixes

C-GULL distinguishes mechanically safe fixes from suggestions requiring developer judgment.

Preview safe replacements without modifying source:

```bash
cgull scan . --fix
```

Apply safe replacements and re-scan:

```bash
cgull scan . --fix --write
```

`--write` requires `--fix`. Review source-control diffs even for mechanically safe changes.

## Parallel scans

The default is one in-process worker:

```bash
cgull scan . -j 1
```

Use a fixed worker count or all available CPUs for larger trees:

```bash
cgull scan . -j 4
cgull scan . -j 0
```

For reproducible performance measurements, use an explicit worker count and keep the analyzed configuration space stable.

## Recommended CI progression

A practical adoption sequence is:

1. run `hybrid` analysis and publish a report without failing the build;
2. define project exclusions, include roots, wrappers, and semantic models;
3. review and commit a baseline if legacy findings remain;
4. gate new high-severity findings with `--fail-on high`;
5. tighten to medium/low as the signal and remediation process mature;
6. optionally require `--fail-on-error` and `--warn-on-fallback` where full analysis coverage is part of the security contract.

See [Development integration](development-integration.md) for concrete pre-commit and GitHub Actions configurations.

## Parser fallback diagnostics

JSON `file_summaries[].parse_attempts` records structural attempts in tier order.
SARIF exposes only `file_path` and `parse_attempts` in
`runs[].properties.file_summaries`, avoiding duplicate counts and timings.
These are additive fields in output schema version `1`; existing report keys and
exit policies are unchanged. Regex-only scans have an empty attempts list.

Each attempt includes `tier`, `status` (`success`, `failure`, or `skipped`),
`exception_category`, a bounded `message`, and `preprocessing_failed`.
`expanded_line`/`expanded_column` are pycparser coordinates including the injected
prelude. `source_line` removes that prelude; `original_file`/`original_line` apply
TU include provenance. `source_column` and `original_column` are null when macro
expansion or normalization prevents a verified column mapping. Unavailable
locations are null. `snippet` contains at most 160 printable characters; messages
contain at most 240. Profile scans additionally identify the attempt's `profile`.
Paths follow the containing report's path policy.

`--warn-on-fallback` prints the failing tiers and reasons on stderr for each
fallback file, and retains its existing exit status of 1. Debug logging also
records fallback reasons. Successful higher-tier parses emit no fallback warning;
a successful regex fallback does not become a scan error. Normal successful-scan
output remains concise, and JSON/SARIF on stdout remain machine-readable.
