# C-GULL 0.11.27 release notes

## Diagnostic logging documentation

C-GULL now documents the Logging v2 operational contract in one place. Normal scans create a project-local JSON Lines diagnostic capture at `<project-state-root>/.cgull/logs/scan-<UTC timestamp>-<pid>.log` unless `--no-log` is supplied. The default threshold is intentionally concise at `WARNING` and above; `-v`, `-vv`, and `-vvv` opt into `INFO`, `DEBUG`, and `TRACE`, while `--log-level LEVEL` explicitly overrides the `-v` selection.

The selected threshold is shared by automatic JSONL capture, interactive stderr diagnostics, and the additive human-readable `--log-file PATH` sink. Detailed INFO/DEBUG/TRACE records are unavailable after the fact unless that detail level was selected for the original scan. `--quiet` only suppresses progress/UI behavior; it does not disable capture or change the log level.

Automatic capture retains 20 C-GULL-owned runs by default. `cgull init` now makes that policy discoverable with:

```toml
[logging]
retention_runs = 20
```

Retention pruning occurs during startup and applies only to automatic C-GULL capture files. Explicit `--log-file` outputs are never retention-managed. Automatic capture setup is fail-open: a local capture failure warns without turning an otherwise valid scan into a logging failure.

Diagnostic records can contain paths, parser messages, rule/configuration context, and bounded source-derived excerpts. C-GULL does not claim automatic secret or PII redaction and does not upload/phone home diagnostic captures. Use `--no-log` when retained local diagnostics are inappropriate for a shared CI or proprietary environment.

Parallel capture remains coordinator-owned: worker diagnostics are transported to the coordinator rather than independently appending to the JSONL file.

## Logging performance reference

Issue #459 measured Logging v2 end to end on the checked-in Juliet slice using Python 3.12.14, file mode, `--jobs 2`, one warm-up cycle, and five measured repetitions per arm. The representative result was:

| Arm | Median throughput | Regression vs no capture |
| --- | ---: | ---: |
| `--no-log` | 0.112055 KLOC/s | baseline |
| default WARNING capture | 0.112479 KLOC/s | **-0.38% — PASS** |
| opt-in TRACE capture | 0.009239 KLOC/s | **+91.75% — informational** |

The default arm met the strict `<2%` release target. The small negative regression should be interpreted as no measurable slowdown on that hosted runner, not as a performance improvement. TRACE is intentionally opt-in and its much higher diagnostic volume is not subject to the default-capture release gate. See `docs/benchmarks/logging-overhead-459.md` for the methodology and raw artifact guidance.
