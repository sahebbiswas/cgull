# Finding profiles and noise reduction

C-GULL ships dozens of rules spanning **security/correctness** (memory, bounds,
injection, crypto) and **MISRA/style policy** (goto, void style, assertions,
unused locals, and similar). On real libraries those policy checks can dominate
raw finding counts without representing exploitable defects. The cJSON first-pass
triage ([epic #550](https://github.com/sahebbiswas/cgull/issues/550)) saw
**222** raw findings where `CGULL-025` and `CGULL-018` alone contributed
**42** each — policy noise beside genuine HIGH rules such as CGULL-001/004/048.

This document records the default profile decision, how to opt into full
MISRA/policy coverage, how baselines fit, and a manual corpus budget checklist
derived from that epic.

## Profiles

| Profile | Intent | Rule selection |
| --- | --- | --- |
| **Focused (security)** — default for `cgull init` | External / security-first scans | Every registered rule **except** the low-severity policy skips below |
| **Comprehensive (MISRA/policy)** | Coding-standard or full-catalog audits | Every registered rule enabled |
| **Custom** | Interactive `cgull init` only | Operator-chosen `[rules.skip]` entries |

Profiles are an **initialization / scan convenience**. Persistent state is always
explicit `[rules.skip]` reasons in `.cgull.toml` (or equivalent CLI merge for a
single scan). There is no hidden profile flag stored in the project file.

### Focused skips (security defaults)

| Rule | Why focused skips it |
| --- | --- |
| `CGULL-018` | `goto` is MISRA C:2012 Rule 15.1 style; common and low security signal on cleanup-oriented C |
| `CGULL-019` | Explicit `void` parameter style is project policy |
| `CGULL-025` | Assertion placement is project policy |

Safety invariant: focused skips **must** stay Low severity. Init and
`--profile focused` refuse to disable HIGH/MEDIUM rules.

Focused does **not** disable HIGH memory/bounds rules (CGULL-001, CGULL-004,
CGULL-007, CGULL-048, …). Noise on those rules is handled by precision fixes,
baselines, and future confidence tiers — not by blanking them in the default pack.

## How to use

### Recommended for a new or external corpus tree

```bash
cgull init --profile focused
cgull scan .
```

Or apply the same skips for one zero-config / ad-hoc scan without writing TOML:

```bash
cgull scan path/to/library.c --profile focused
```

Prefer focused for third-party corpus scans and security CI gates so MISRA/style
hits do not drown actionable findings.

### Enable comprehensive / MISRA coverage

```bash
cgull init --profile comprehensive
# or, with an existing focused config, remove the [rules.skip] entries for
# CGULL-018 / CGULL-019 / CGULL-025, then:
cgull scan .
```

Comprehensive is appropriate when the goal is coding-standard compliance rather
than a security-first triage.

### Report labeling (security vs policy)

Human text and Markdown summaries split findings into:

- **Security actionable** — memory, bounds, injection, crypto, and other
  non-policy categories;
- **Policy / quality** — `RuleCategory` style/MISRA rules plus MISRA control-flow
  policy IDs `CGULL-017` and `CGULL-018`.

Labeling is **report-only**: it does not change exit codes, baselines, or which
rules run. Even on a comprehensive scan, “42 gotos” read as policy/quality rather
than 42 vulnerabilities.

## Baselines

When a mature tree still has accepted security findings after a focused profile:

```bash
cgull scan . --profile focused --update-baseline .cgull-baseline.json
cgull scan . --profile focused --baseline .cgull-baseline.json --fail-on high
```

Treat baseline edits as reviewed security-policy changes. Use equivalent scan
inputs (engine, profile/skips, mode, config strategy) when creating and
consuming a baseline. See [Reporting and CI](reporting-and-ci.md).

## Corpus budget checklist (cJSON epic #550)

Manual regression checklist for pinned **cJSON v1.7.18** (`cJSON.c` + `cJSON.h`)
after a focused security scan. Re-run with the same C-GULL version, engine, and
`--profile focused` (or an equivalent focused `.cgull.toml`) before claiming a
noise-reduction improvement.

```bash
pip install -e ".[ast]"
cgull scan path/to/cJSON.c path/to/cJSON.h --engine hybrid --severity all \
  --profile focused --format json -o cjson-scan.json
```

Optional faster iteration (validate parity first): `--config-strategy baseline`.

| Class / rule | Budget intent |
| --- | --- |
| `CGULL-011` illegal fn-ptr conversions | **0** (export-macro FPs should stay fixed) |
| `CGULL-034` div-by-zero | **0** (`NAN` / NaN-literal FPs should stay fixed) |
| `CGULL-023` uninitialized use | **0** FP class for decl-without-init ≠ use-before-init |
| `CGULL-018` / `CGULL-019` / `CGULL-025` | **0** under focused (skipped by profile) |
| `CGULL-004` missing null check | Track ceiling; prefer precision fixes over skip |
| `CGULL-007` array OOB | Track ceiling; prefer loop/bounds precision |
| `CGULL-001` banned functions | Expect real `sprintf`/`strcpy` TPs; baseline if accepted |
| `CGULL-048` buffer copy overflow | Mix; do not hide without baseline intent |
| Raw total vs security-actionable count | Prefer summarizing by **security actionable** in reports |

Non-goals for this checklist: blindly disabling HIGH memory/bounds rules, or
shipping a default that hides real CGULL-001/048 hits without an explicit
baseline decision.

Further automation (pinned corpus CI asserting these ceilings) remains optional
follow-up under epic #550 / issue #561.
