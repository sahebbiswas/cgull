# Scan parallelism

C-GULL keeps explicit worker control through `-j` / `--jobs`, while choosing a safer default for normal project scans.

## CLI defaults

When `--jobs` is omitted:

- a directory target such as `cgull scan .` or `cgull scan src/` uses bounded automatic parallelism;
- mixed targets that contain a directory also use bounded automatic parallelism;
- file-only targets remain sequential by default, including a direct `cgull scan file.c` invocation.

Automatic CLI selection uses the available logical CPU count but caps the initial worker limit at **8**. After file discovery, the scanner already caps the effective worker count to the number of files that will actually be scanned. As a result, a directory containing only one scan target remains in the sequential path instead of starting a worker pool.

The cap is a CLI policy intended to avoid excessive process and memory pressure on machines with very high CPU counts. The programmatic `CGullScanner.scan_path(..., jobs=1)` default is unchanged.

## Explicit control

Explicit values always win:

```bash
cgull scan . --jobs 1   # force sequential execution
cgull scan . --jobs 4   # use up to four workers
cgull scan . --jobs 0   # bounded automatic CLI selection
```

`--jobs N` with `N > 1` requests that worker count, subject to the scanner's existing post-discovery cap when fewer files are available. Negative values remain invalid.

For library callers, `scan_path(..., jobs=0)` retains the existing API meaning of automatic CPU-count selection. The bounded eight-worker policy is applied only by the CLI before calling the scanner, preserving programmatic compatibility.

## Reporting

CLI reports expose both the effective worker count and how it was selected:

- terminal and Markdown output show `Workers` and `Worker source`;
- JSON adds `meta.jobs` and `meta.jobs_source`;
- SARIF invocation properties add `jobs` and `jobsSource`.

Worker source is one of:

- `explicit` for `--jobs 1` or another positive count;
- `automatic` for directory-default parallelism or `--jobs 0`;
- `sequential default` for an omitted `--jobs` on file-only targets.

The reported worker count is the effective count after the scan workload is known, so a tiny directory may report fewer workers than the automatic limit.

## Determinism

Parallel and sequential scan paths use the same scan configuration and the engine sorts findings, file summaries, failures, and diagnostics before returning a result. Changing worker selection therefore changes scheduling rather than report ordering or finding identity.

Project/TU preparation is currently performed before the file-worker stage. Further parallelization of that preparation phase is tracked separately in issue #488; this CLI default does not change its semantics.
