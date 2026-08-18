# C-GULL 0.6.0 Release Notes

Welcome to the initial public release of **C-GULL** (Code Guardian for Unchecked Logic & Leaks)! 

C-GULL is a lightweight, modular C source code static security analyzer designed to identify common memory vulnerabilities, buffer overflows, format string flaws, timing side-channel patterns, and MISRA-C compliance guidelines.

## 🚀 Key Features in Initial Release

- **⚡ Dual Analysis Engine**:
  - **Lightweight Regex Pattern Matching**: Fast first-pass scanning for banned API calls, format strings, and unsafe casts.
  - **AST & CFG-Assisted Structural Analysis**: Structural and control-flow aware pattern checks for unchecked `malloc` returns, missing pointer NULL checks, and use-after-free, powered by `pycparser` and `pcpp`.
- **🛡️ 25 Security Audit Rules**: Comprehensive rule coverage spanning memory safety, cryptography, control flow, arithmetic, and code quality.
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
