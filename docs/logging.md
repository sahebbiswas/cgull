# Diagnostic logging

C-GULL keeps diagnostic logging separate from scan reports. Report payloads are findings and scan metadata selected with `--format`/`--output`; diagnostic logs are operational records intended to explain parser, configuration, rule, and runtime behavior.

A normal scan creates a local structured diagnostic capture unless `--no-log` is supplied. The default capture is intentionally concise: it records only `WARNING` and `ERROR` diagnostics. More detailed records exist after the scan only when that verbosity was selected for the original run. Without that original selection, those detailed records are unavailable after the fact.

## Verbosity model

All diagnostic sinks use one effective threshold:

| Selection | Captured/displayed diagnostics |
| --- | --- |
| none | `WARNING` and above |
| `-v` | `INFO` and above |
| `-vv` | `DEBUG` and above |
| `-vvv` | `TRACE` and above |
| `--log-level LEVEL` | explicit level; overrides `-v`/`-vv`/`-vvv` |

The same effective threshold applies to:

- automatic JSON Lines capture;
- interactive diagnostics on `stderr`;
- the optional human-readable `--log-file PATH` sink.

INFO, DEBUG, and TRACE records are **not** retained secretly when the default WARNING threshold is active. If a difficult scan may need full post-hoc diagnostics, run it with `-vvv` or `--log-level trace` from the start.

`--quiet` suppresses progress/UI behavior. It does not disable diagnostic capture and does not change the selected log level.

## Capture and report streams

Automatic capture is local and enabled unless `--no-log` is supplied. Diagnostics remain on `stderr`; report payloads remain on `stdout` unless `--output` is used. This keeps stdout safe for text, JSON, SARIF, and Markdown report consumers.

C-GULL does not upload diagnostic captures or send them to a remote collection service. Automatic capture is a project-local filesystem feature.

## Default location

Automatic captures use:

```text
<project-state-root>/.cgull/logs/scan-<UTC timestamp>-<pid>.log
```

Each file is JSON Lines (JSONL): one structured diagnostic record per line.

The project-state root is resolved from scan/configuration context. An existing explicitly selected configuration file establishes the root at its directory. Otherwise C-GULL uses the discovered project configuration directory when one exists; without configuration it uses the effective/common scan-target directory. This keeps retained diagnostics with the project being analyzed rather than in a global user directory.

## Retention

C-GULL retains 20 automatic capture runs by default. Configure a different positive run count in `.cgull.toml` or the equivalent `[tool.cgull]` section of `pyproject.toml`:

```toml
[logging]
retention_runs = 20
```

The exact configuration key is `[logging].retention_runs`.

Retention cleanup happens during logging startup. C-GULL prunes only files matching its automatic `scan-<timestamp>-<pid>.log` naming scheme, and it makes room for the current run before opening the new capture. Unrelated files in `.cgull/logs/` are not retention-managed.

An explicit `--log-file PATH` is also not retention-managed. It remains exactly where the user requested it.

If the automatic log directory cannot be created, pruned, or opened, diagnostic capture fails open: C-GULL warns once for the setup failure and continues the scan. An explicit `--log-file PATH` error remains an explicit user-requested logging error rather than being silently redirected elsewhere.

## Privacy and content boundary

Diagnostic records can contain information useful for debugging, including:

- filesystem paths;
- parser/preprocessor messages;
- rule and configuration context;
- bounded source-derived excerpts when a diagnostic call site supplies one.

Bounded excerpts reduce retained volume; they do **not** guarantee that sensitive source content is absent. C-GULL does not claim automatic secret or PII redaction for diagnostic logs.

For shared CI workers, proprietary build environments, ephemeral runners, or any environment where local retention is inappropriate, use:

```bash
cgull scan . --no-log
```

That disables the automatic JSONL capture. It does not suppress normal `stderr` diagnostics at the selected level.

## `--log-file` compatibility

`--log-file PATH` remains a human-readable text log written at exactly `PATH`. It follows the same effective verbosity as stderr and automatic capture, and it is additive to automatic JSONL capture.

`--no-log` disables only the default automatic JSONL capture. It does not disable an explicitly requested `--log-file`.

Examples:

```text
cgull scan src                         => JSONL WARNING+
cgull scan src -v                      => JSONL + stderr INFO+
cgull scan src -vv                     => JSONL + stderr DEBUG+
cgull scan src -vvv                    => JSONL + stderr TRACE+
cgull scan src --log-file run.log      => JSONL WARNING+ + run.log WARNING+
cgull scan src --no-log                => no default JSONL; stderr WARNING+
cgull scan src -vvv --no-log --log-file run.log
                                        => run.log + stderr TRACE+, no default JSONL
```

There is no `--log-file` deprecation: the text log and automatic JSONL capture serve different compatibility/use cases.

## Parallel scans

For `-j N` scans, worker diagnostics are forwarded to coordinator-owned logging handlers. Workers do not independently append to the automatic capture file, so one scan produces one coordinator-owned JSONL stream rather than competing per-worker writes.

Progress rendering is also coordinator-owned and stays on `stderr`. Progress telemetry and persistent diagnostic capture are related operational surfaces but are not the same data model; see [Scan telemetry](scan-telemetry.md).

## Performance expectations

Issue #459 added an end-to-end Juliet logging benchmark comparing `--no-log`, default WARNING capture, and opt-in TRACE capture. The checked-in 2026-09-14 reference run used Python 3.12.14, file mode, `--jobs 2`, one warm-up, and five measured repetitions per arm.

| Arm | Median throughput | Regression vs no capture |
| --- | ---: | ---: |
| no capture | 0.112055 KLOC/s | baseline |
| default WARNING capture | 0.112479 KLOC/s | -0.38% (PASS) |
| TRACE capture | 0.009239 KLOC/s | +91.75% (informational) |

The default result means no measurable default-capture slowdown was observed on that hosted runner and met the `<2%` target. The small negative regression is best interpreted as **no measurable default-capture slowdown on this hosted runner**, not as evidence that logging improves performance. TRACE intentionally captures much higher diagnostic volume and is opt-in; its reference overhead is informational rather than a release gate. See [Logging capture overhead benchmark](benchmarks/logging-overhead-459.md) for methodology, raw-sample guidance, and the point-in-time nature of those numbers.

## Choosing a mode

Use the default when warnings/errors are enough and local retention is acceptable. Use `-v`/`-vv` while debugging increasing levels of scanner behavior. Use `-vvv` or `--log-level trace` when a full diagnostic trace is worth the additional I/O and runtime cost. Use `--no-log` when retained local diagnostics are inappropriate, and combine it with `--log-file PATH` when an explicitly managed human-readable artifact is preferred.
