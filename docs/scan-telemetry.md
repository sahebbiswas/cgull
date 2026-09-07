# Scan telemetry

C-GULL reports scan-level telemetry so users can see how much source was scanned and how quickly analysis progressed. These counters describe scanner workload; they do not affect findings, filtering, failure thresholds, or exit status.

## Metric definitions

### Lines scanned (`unique_source_lines`)

`unique_source_lines` is the number of **physical lines in unique eligible source files participating in the scan**.

- Blank lines, comments, and preprocessor directives count as physical lines.
- A physical file contributes once even when the same target is supplied more than once.
- Ignored or excluded files do not contribute.
- A file without a trailing newline still counts its final physical line.

The human-readable label for this metric is **Lines scanned**. C-GULL intentionally does not describe it as semantic LOC because it includes comments, blanks, and preprocessing text.

### Analysis volume (`analyzed_lines`)

`analyzed_lines` is the cumulative number of physical source lines processed by analysis work across scan units and configuration/profile passes.

For a normal single-pass file scan, `analyzed_lines` equals `unique_source_lines`. If the same source is analyzed under multiple configuration profiles, `analyzed_lines` can be larger than `unique_source_lines` because it represents repeated scanner work rather than unique source size.

### Throughput (`throughput_kloc_per_sec`)

C-GULL reports average analysis throughput as:

```text
throughput_kloc_per_sec = analyzed_lines / 1000 / elapsed_seconds
```

Elapsed time uses a monotonic wall clock. Throughput is the average since analysis began, not an instantaneous rolling rate and not files per second. Empty or effectively zero-duration scans report `0.0` rather than `NaN` or infinity.

### Other scan counters

The same telemetry object also reports:

- `files_discovered`: eligible and ignored source files discovered for the scan.
- `files_scanned`: files successfully analyzed.
- `findings_count`: findings present in the final result (after baseline filtering when a baseline is used).
- `parse_fallback_count`: successfully analyzed files that required the fallback parser path.
- `scan_error_count`: scan errors recorded by the coordinator.

## Live progress

The existing progress indicator remains a single coordinator-owned stream on **stderr**. As files complete, it can include cumulative analysis volume, average KLOC/s, and findings observed so far. Worker processes never print independent progress lines.

`--quiet` suppresses live progress. Report data written to stdout therefore remains valid JSON, SARIF, Markdown, or text while progress is enabled.

Example:

```text
Scanning [██████░░░░░░░░░░░░░░] 30% (184/527 files)  •  82.4 KLOC  •  14.7 KLOC/s  •  6 issues
```

## Final reports

All report formats consume the same finalized telemetry values:

- **Text** ends with a `Scan complete` summary containing files scanned, lines scanned, optional repeated analysis volume, analysis time, throughput, findings, parser fallbacks, and scan errors.
- **JSON** exposes telemetry in the top-level `scan` object.
- **SARIF** stores telemetry in `runs[].invocations[].properties.scanMetrics` and does not create synthetic findings.
- **Markdown** includes a compact `Scan Summary` table.

Telemetry is observational only. Baseline filtering preserves the original scan volume and timing while updating `findings_count` to match the filtered result.