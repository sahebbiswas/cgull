# C-GULL 0.6.0 Release Notes

Welcome to the initial public release of **C-GULL** (Code Guardian for Unchecked Logic & Leaks)! 

C-GULL is a lightweight, modular C source code static security analyzer designed to identify common memory vulnerabilities, buffer overflows, format string flaws, timing side-channel patterns, and MISRA-C compliance guidelines.

## 🚀 Key Features in Initial Release

- **⚡ Dual Analysis Engine**:
  - **Lightweight Regex Pattern Matching**: Fast first-pass scanning for banned API calls, format strings, and unsafe casts.
  - **AST & CFG-Assisted Structural Analysis**: Structural and control-flow aware pattern checks for unchecked `malloc` returns, missing pointer NULL checks, and use-after-free, powered by `pycparser` and `pcpp`.
- **🛡️ 46 Security Audit Rules**: Comprehensive rule coverage (CGULL-001 through CGULL-046) spanning memory safety, cryptography, control flow, arithmetic, struct/array buffer overflows, dead-store detection, variable shadowing, pointer scaling, missing inclusion guards, and MISRA-C compliance.
- **🔇 Inline Suppression**: Silence specific findings using inline comments (e.g., `// cgull-ignore: CGULL-001`).
- **⚙️ Parallel Scanning**: Multi-core scanning support for large codebases (`-j/--jobs`).
- **📏 Baseline / Diff Mode**: CI enforcement for "no *new* issues" on an existing codebase (`--baseline` and `--update-baseline`).
- **📊 Multi-Format Reporting**: JSON, SARIF 2.1.0, Markdown, and colored terminal outputs.
- **🚫 .cgullignore Support**: Easily exclude vendor libraries, third-party dependencies, or test mock files using gitignore glob patterns.
- **🧩 Extensible Architecture**: Easily add custom regex or AST rules using the object-oriented Python class interface.

## 📦 Installation

```bash
pip install cgull
# For best AST analysis:
pip install "cgull[ast]"
```

Check out the [README](README.md) for full documentation, CLI usage, and extension examples!

## ⚡ Config-Space Scanning & Reachability Benchmark (v0.8.45)

C-GULL now supports per-configuration static scanning and condition-tagged finding reachability (`reachable_under`).
Findings produced across configuration variants (`List[ConfigProfile]`) are automatically merged by fingerprint:
- Findings active under a subset of configurations are tagged with their specific profile labels (e.g. `["+LEGACY_AUTH"]`).
- Findings produced under every scanned configuration are tagged as `["unconditional"]`.

### ⏱️ Performance Footprint on `examples/`
Wall-clock scan duration benchmarks on the `examples/` directory:
- **Single-Pass Baseline Scan (1 run)**: ~0.378s
- **Multi-Config Variant Scan (3 profiles: baseline, +DEBUG, +LEGACY_AUTH)**: ~0.967s (linear N+1 scaling with profile count)

## ⚡ Translation-Unit Mode: Preprocessed-Unit Caching Benchmark

Translation-Unit (`--mode tu`) mode now caches the expanded-and-parsed representation of each header keyed on its resolved path and SHA256 content hash, so headers pulled into multiple TUs are lexed and expanded once per `cgull` scan invocation and reused across TUs. Caches invalidate automatically on content hash mismatch.

### ⏱️ Synthetic Multi-File Fixture Benchmark (`--engine ast --mode tu`)
Wall-clock scan duration benchmark on a synthetic multi-file fixture (1 shared header with 100 declarations included by 50 small `.c` files):
- **Uncached Header Expansion**: ~1.84s
- **Cached Header Expansion**: ~1.70s (~1.08x speedup)

## Interprocedural release gates (v0.9.51)

The intra-TU interprocedural milestone now has a machine-readable release gate that checks deterministic findings across repeated, file/TU, sequential/parallel, and configuration-profile scans. It also records per-rule precision/recall deltas and benchmarks representative, macro-heavy, deep-wrapper, and recursive-SCC workloads against documented wall-time and peak-memory budgets.

The gate includes explicit safe/unsafe coverage for the data-dependent `CGULL-001` `scanf` policy and verifies that fixed-point limit exhaustion remains visible through `CONVERGENCE_LIMIT` diagnostics rather than failing silently.

This release gate does **not** imply whole-program analysis. Cross-TU analysis, full points-to analysis, path-sensitive symbolic execution, concurrency reasoning, and arbitrary function-pointer resolution remain deferred.
