# 🛡️ C-GULL: Code Guardian for Unchecked Logic & Leaks

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Security Standards](https://img.shields.io/badge/standards-MISRA--C%20%7C%20CWE%20%7C%20CERT--C-orange.svg)](https://cwe.mitre.org/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

**C-GULL** (*Code Guardian for Unchecked Logic & Leaks*) is a lightweight, modular C source code static security analyzer designed to assist with identifying common C memory vulnerabilities, buffer overflow risks, format string flaws, timing side-channel patterns, and select MISRA-C compliance guidelines.

Built for both lightweight regex scans and AST-assisted analysis (using a built-in C structural parser, cross-checked by `pycparser` when available -- see "AST Engine Notes" below), C-GULL generates vulnerability reports in **JSON**, **OASIS SARIF v2.1.0**, **Markdown**, and **colored terminal formats**.

---

## 🚀 Key Features

- **⚡ Dual Analysis Engine**:
  - **Lightweight Regex Pattern Matching**: fast first-pass scanning for banned API calls, format strings, unsafe casts, and suspicious macros. Runs against a comment-stripped and string-literal-masked view of the source to reduce basic false matches.
  - **AST & CFG-Assisted Structural Analysis**: structural and control-flow aware pattern checks for unchecked `malloc` returns, missing pointer NULL checks, use-after-free (now branch, loop, and switch-sensitive), VLAs, and control flow patterns, built on a lightweight in-repo C parser and cross-checked with `pycparser` where supported.
- **🛠️ Project Configuration File (TOML)**: Auto-discovered `.cgull.toml` or `pyproject.toml` `[tool.cgull]` for project-wide rule skipping, per-rule severity overrides, path exclusions, output defaults, custom allocator/deallocator synonyms (e.g. `xmalloc`/`xfree`, `kmalloc`/`kfree`), and custom banned function wrappers.
- **🔇 Inline Suppression**: silence specific findings with `// cgull-ignore`, `// cgull-disable-next-line CGULL-007`, `/* cgull-disable-line CGULL-019 */`, or `// cgull-ignore-next-line: CGULL-001,CGULL-003`.
- **⚙️ Parallel Scanning**: `-j/--jobs` scans multiple files concurrently across CPU cores for larger codebases.
- **📏 Baseline / Diff Mode**: `--baseline`/`--update-baseline` let CI enforce "no *new* issues" on an existing, imperfect codebase instead of requiring it to already be fully clean -- see "Baseline / Diff Mode" below.
- **📁 Recursive Directory Scanning**: Automatically discovers and audits C source and header files (`.c`, `.h`) across nested codebases.
- **🚫 .cgullignore Support**: Exclude vendor libraries, third-party dependencies, build output directories, or test mock files using standard gitignore glob patterns and negations (`!`).
- **📊 Multi-Format Reporting**:
  - Structured **JSON** for automated ingestion and reporting dashboards.
  - **SARIF 2.1.0** for native integration into GitHub Code Scanning and GitLab SAST.
  - **Executive Markdown** summary tables with remediation guides and clear distinction between automatic fixes, suggested fixes, and manual review items.
- **🧩 Extensible & Modular Architecture**: Add new custom regex or AST rules with a clean object-oriented class interface.
- **🧪 Test Suite**: `unittest` suite covering security rules plus regression tests for known false-positive patterns.

### AST Engine Notes (please read before trusting AST-tagged findings)

`pycparser` cannot parse raw, unpreprocessed C — it has no definition for `size_t`, `uint32_t`, or anything from an `#include`d header, and chokes on macro-dependent syntax. C-GULL uses a **three-tier strategy** to maximize the fraction of files that get a real AST parse:

1. **`pcpp` + `pycparser`** (best, when both are installed): [`pcpp`](https://pypi.org/project/pcpp/) is a pure-Python C99 preprocessor that expands `#define` macros and evaluates `#ifdef`/`#if` conditionals *within the file*, producing output that `pycparser` can parse. This handles the common case of code that depends on in-file macro definitions (e.g. `#define BUF_SIZE 128` → `char buf[BUF_SIZE];`). `#include` directives for unavailable headers are silently passed through and stripped before parsing.

2. **Directive stripping + `pycparser`** (good, when only `pycparser` is installed): Preprocessor directives are stripped and a small typedef prelude is injected. This works for code that does not structurally depend on macro expansion.

3. **Regex extractor** (fallback, always available): A lightweight regex/brace-counting extractor for function and variable structure. Weaker (e.g. it cannot represent multi-declarator lines like `int a, b, c;` on its own) but never crashes the scan.

In all cases, files that rely on external header definitions, project-specific typedefs, or complex macro expansion patterns may still fail the AST parse and fall back to the regex extractor. Each file's result surfaces its exact parse tier (`pcpp+pycparser`, `directive-stripped`, or `regex-fallback`) in `file_summaries`. CI pipelines can enforce full AST parsing by passing `--warn-on-fallback` (or setting `warn_on_fallback = true` in config) to fail the build whenever a file falls back to `regex-fallback` mode.

---

## 📦 Installation

### Option 1: Direct Python Execution (Zero External Dependencies)
C-GULL's core engine runs on standard Python 3.10+ with **no third-party dependencies required**:
```bash
# Clone the repository
git clone https://github.com/sahebbiswas/cgull.git
cd cgull

# Run directly via Python module
python3 -m cgull scan src/
```

### Option 2: Install via pip (Editable Development Mode)
```bash
pip install -e .
```

### Option 3: Optional AST Parser Enhancement (`pycparser` + `pcpp`)
```bash
# Install both pycparser and pcpp for best AST analysis:
pip install -e ".[ast]"

# Or install individually:
pip install pycparser   # AST parsing
pip install pcpp        # C preprocessor (macro expansion)
```


---

## 💻 CLI Usage & Commands

### Basic Scan
```bash
# Scan current directory recursively (auto-discovers .cgull.toml or pyproject.toml)
cgull scan .

# Scan specific source directory with an explicit config file
cgull scan src/ --config .cgull.toml

# Scan a single C file
cgull scan main.c
```

### Generating JSON Reports
```bash
# Export audit report to JSON
cgull scan src/ -o security-report.json --format json
```

### Generating SARIF Reports for CI/CD
```bash
# Export SARIF for GitHub Advanced Security / GitLab SAST
cgull scan src/ -o results.sarif --format sarif
```

### Filtering by Severity & Engine
```bash
# Scan only High impact vulnerabilities using fast Regex engine
cgull scan src/ --severity high --engine regex

# Run deep AST inspection on entire codebase
cgull scan src/ --engine ast
```

### Parallel Scanning
```bash
# Scan sequentially in-process (default)
cgull scan src/ -j 1

# Scan files across 4 worker processes
cgull scan src/ -j 4

# Auto-detect and use all available CPU cores (0)
cgull scan src/ -j 0
```
`-j`/`--jobs` options:
- `1`: sequential in-process scanning (default)
- `N > 1`: parallel scanning across `N` worker processes
- `0`: auto-detect and use all available CPU cores
- Negative values (e.g. `-j -1`): invalid, produces an error

### Project Configuration File (.cgull.toml / pyproject.toml)

C-GULL supports auto-discovered project configuration via a standalone `.cgull.toml` file or a `[tool.cgull]` table inside `pyproject.toml`. Explicit `--config path/to/config.toml` overrides auto-discovery.

```toml
# .cgull.toml (schema_version = 1)
schema_version = 1

[rules]
# Rule IDs to skip entirely, mapped to justification strings
skip = { "CGULL-019" = "team does not follow MISRA explicit-(void) style" }

[rules.severity]
# Per-rule severity overrides
CGULL-024 = "high"   # hardcoded secrets: always treat as high
CGULL-020 = "low"    # unused arguments: downgrade to low

[functions.memory]
# Extends built-in malloc/calloc/realloc/free recognition
# for unchecked allocation (CGULL-003) and use-after-free (CGULL-022 / CGULL-027)
alloc   = ["xmalloc", "kmalloc", "OPENSSL_malloc", "talloc"]
realloc = ["xrealloc", "krealloc"]
dealloc = ["xfree", "kfree", "OPENSSL_free", "talloc_free"]

[functions.banned]
# Custom project-specific banned functions (extends CGULL-001)
[functions.banned.legacy_string_copy]
reason = "in-house wrapper around strcpy() with no bounds checking"
remediation = "use safe_string_copy(dest, sizeof(dest), src) instead"

[paths]
# Combined with .cgullignore (additive)
exclude = ["third_party/", "generated/"]

[output]
default_format = "sarif"
fail_on = "high"
warn_on_fallback = true
```

### Suppressing Findings Inline
```c
strcpy(dest, src);                        // cgull-ignore: CGULL-001
strcpy(dest, src);                        // cgull-ignore              (suppresses every rule on this line)
// cgull-disable-next-line CGULL-007
arr[i] = 0;
/* cgull-disable-line CGULL-019 */
int my_func() {}
// cgull-ignore-next-line: CGULL-001,CGULL-003
strcpy(dest, src);
```

### Baseline / Diff Mode

Adopting a scanner on an existing, imperfect codebase is usually impractical if `--fail-on high` fails the build on every pre-existing issue on day one. Baseline mode fixes that: snapshot the findings you're accepting for now, then only fail CI on findings introduced *after* that snapshot.

A baseline file is just an ordinary `cgull scan --format json` report -- there's no separate format. Findings are matched between scans by a content-based fingerprint (rule + file + normalized code snippet), not line number, so unrelated edits elsewhere in a file won't make an untouched finding look "new".

```bash
# 1. Snapshot current findings as the accepted baseline (commit this file)
cgull scan src/ --update-baseline .cgull-baseline.json

# 2. In CI: only fail on issues introduced since the baseline
cgull scan src/ --baseline .cgull-baseline.json --fail-on medium

# --update-baseline and --baseline can be combined in one invocation to
# both check against the current baseline AND immediately refresh it:
cgull scan src/ --baseline .cgull-baseline.json --update-baseline .cgull-baseline.json --fail-on medium
```

The report (any format) shows both the new-issue count and how many baseline findings have since been resolved:

```
Baseline Diff    : 12 total, 1 new, 3 resolved since baseline
```

> **Note:** run the baseline snapshot and the later diffed scan with the same `--severity`/`--engine` flags. A baseline captured with `--severity all` compared against a later scan run with `--severity high` will make the filtered-out medium/low findings look "resolved" even though they were just excluded, not fixed.

### CI/CD Pipeline Enforcement (Fail on Severity Threshold)
```bash
# Exits with non-zero exit code if issues at or above severity threshold are found
cgull scan src/ --fail-on high
cgull scan src/ --fail-on medium
cgull scan src/ --fail-on low

# Note: --fail-on-high is supported as a backward-compatible alias for --fail-on high
cgull scan src/ --fail-on-high

# Exits with code 1 if AST parsing falls back to regex-fallback mode for any file
cgull scan src/ --warn-on-fallback
```

### Listing All Active Rules
```bash
cgull rules
```

### Initializing a `.cgullignore` File
```bash
cgull init-ignore
```

---

## 🛡️ Supported Security Rules Matrix

C-GULL implements the security audit rules listed below:

| Rule ID | Rule Name | Impact | Category | CWE ID | Method | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CGULL-001** | Banned Functions | **High** | Strings | CWE-676 / 120 / 377 | Regex | Flags insecure legacy functions (`gets`, `strcpy`, `strcat`, `sprintf`, `scanf %s`, `mktemp`, `tmpnam`, `tempnam`). |
| **CGULL-002** | Format String Vulnerabilities | **High** | Strings | CWE-134 | Hybrid | Detects non-literal format strings in `printf(buf)` and `syslog`. |
| **CGULL-003** | Unchecked Dynamic Allocations | **High** | Memory | CWE-476 / 252 | AST | Ensures `malloc`, `calloc`, `realloc` returns are checked against NULL before dereference. |
| **CGULL-004** | Missing Null Check on Params | **High** | Memory | CWE-476 | AST | Flags pointer parameters dereferenced without prior NULL verification. |
| **CGULL-005** | Non-Constant Time Comparison | **High** | Crypto | CWE-208 / 385 | Hybrid | Flags `memcmp()`/`strcmp()` in cryptographic & authentication contexts (timing attack). |
| **CGULL-006** | Arithmetic Integer Overflow | **High** | Arithmetic | CWE-190 / 680 | Hybrid | Detects unchecked arithmetic (`*`, `+`) in allocation sizes or offsets. |
| **CGULL-007** | Array Index Out of Bounds | **High** | Memory | CWE-129 / 125 | Hybrid | Identifies unconstrained or out-of-range array index operations. |
| **CGULL-008** | Unsafe Sensitive Memory Clearing | **High** | Crypto | CWE-14 | Hybrid | Detects `memset()` on sensitive local buffers before return (Dead Store Elimination). |
| **CGULL-009** | Stripping Volatile Qualifiers | **High** | Control Flow | CWE-562 / 704 | Hybrid | Prevents unsafe casts removing `volatile` from MMIO registers or shared state. |
| **CGULL-010** | Variable Length Arrays (VLAs) | **High** | Memory | CWE-400 / 787 | AST | Forbids runtime variable-sized stack arrays (`char buf[len]`) to prevent stack smashing. |
| **CGULL-011** | Illegal Func Pointer Conversions | **High** | Control Flow | CWE-843 / 588 | Hybrid | Prevents function pointer conversions to `void*` or integers (ROP / CFI mitigation). |
| **CGULL-012** | Unsafe Integer Conversions | **Medium** | Arithmetic | CWE-704 | Regex | Flags `atoi`, `atol`, `atoll` which lack overflow and error handling (suggests `strtol`). |
| **CGULL-013** | Naked Control Flow Statements | **Medium** | Control Flow | CWE-483 | Hybrid | Enforces curly braces `{}` for `if`, `else`, `for`, `while` statements (MISRA C:2012). |
| **CGULL-014** | Use of Magic Numbers | **Medium** | Code Quality | CWE-1094 | Hybrid | Flags hardcoded magic numbers in array declarations and memory allocations. |
| **CGULL-015** | Bitwise Ops on Signed Integers | **Medium** | Arithmetic | CERT INT13-C | Hybrid | Flags bitwise shifts and masks performed on signed integers (Undefined Behavior). |
| **CGULL-016** | Single-Point-of-Failure Control | **Medium** | Control Flow | CWE-1240 | AST | Flags simple boolean returns (1/0) in security/auth functions vulnerable to fault glitching. |
| **CGULL-017** | Missing default in Switch | **Low** | MISRA | MISRA 16.4 | AST | Enforces mandatory `default:` label in all switch statements. |
| **CGULL-018** | Use of goto Statements | **Low** | MISRA | MISRA 15.1 | Regex | Flags unstructured `goto` jumps that bypass initializations. |
| **CGULL-019** | Missing void in Parameter Lists | **Low** | MISRA | MISRA 8.2 | AST | Requires explicit `(void)` for functions with empty argument lists (`int init(void)`). |
| **CGULL-020** | Unused Arguments | **Low** | Code Quality | CWE-563 | AST | Detects function parameters declared but never referenced in function bodies. |
| **CGULL-021** | Uninitialized Pointers | **High** | Memory | CWE-457 | Hybrid | Detects wild pointers declared without explicit `NULL` or memory initialization. |
| **CGULL-022** | Use-After-Free | **High** | Memory | CWE-416 | AST | Tracks pointer lifecycle to flag dereferencing of freed memory addresses. |
| **CGULL-023** | Uninitialized Memory Use | **High** | Memory | CWE-457 | AST | Identifies local variables read before explicit assignment. |
| **CGULL-024** | Insecure Data Storage | **Medium** | Crypto | CWE-312 / 798 | Regex | Flags hardcoded passwords, tokens, and encryption keys in plaintext static memory. |
| **CGULL-025** | Missing Assertions | **Low** | Code Quality | CWE-617 | AST | Enforces `assert()` validations for state invariants in critical complex routines. |
| **CGULL-026** | Unchecked snprintf() Return Value | **High** | Strings | CWE-131 | Regex | Flag the direct accumulation of snprintf() return value into an offset without checking for truncation. snprintf() returns the number of bytes it *would* have written, leading to underflow if used directly on truncation. |
| **CGULL-027** | Double Free | **High** | Memory | CWE-415 | Ast | Detect calling free() on a pointer that has already been freed. |
| **CGULL-028** | Insecure PRNG for Security Use | **High** | Crypto | CWE-338 | Hybrid | Flags `rand()`, `random()`, or `srand(time(NULL))` calls in security-sensitive contexts. |
| **CGULL-029** | sizeof() on Pointer Type | **High** | Arithmetic | CWE-467 | AST | Flags use of `sizeof()` on a pointer variable, which returns the size of the pointer instead of the memory block. |
| **CGULL-030** | Command Injection Vulnerability | **High** | Control Flow | CWE-78 | Hybrid | Flags use of `system()`, `popen()`, or PATH-searching `exec` variants (`execlp`/`execvp`/`execvpe`/`execlpe`) with non-literal string arguments. |
| **CGULL-031** | Weak/Broken Crypto Primitives | **High** | Crypto | CWE-327 | Hybrid | Detects calls to weak or broken cryptographic algorithms (`MD5`, `SHA-1` in security contexts, `DES_*`, `RC4`, `EVP_*` ECB cipher mode variants). |
| **CGULL-032** | Realloc-Overwrite Memory Leak | **High** | Memory | CWE-401 | Hybrid | Detects `x = realloc(x, ...)` directly overwriting pointer variable before NULL check, leaking memory on OOM. |
| **CGULL-033** | Signed/Unsigned Comparison | **Medium** | Arithmetic | CWE-195 / INT02-C | Hybrid | Detects signed/unsigned integer comparisons and loop-bound mismatches causing infinite loops or promotion bugs. |
| **CGULL-034** | Division or Modulo by Zero | **High** | Arithmetic | CWE-369 | Hybrid | Detect division (/) or modulo (%) operations where the divisor might be zero, causing a crash or undefined behavior. |
| **CGULL-035** | TOCTOU File Access | **High** | Control Flow | CWE-367 | Hybrid | Detects time-of-check to time-of-use race conditions where file checks (access, stat) are followed by file operations (open, fopen, chmod). |

---

## 🚫 `.cgullignore` Specification

Create a `.cgullignore` file in your project root to exclude directories, files, or specific pattern masks:

```gitignore
# Exclude vendor dependencies and third-party code
vendor/
third_party/
deps/

# Exclude build artifacts
build/
dist/
*.o
*.obj
*.so

# Exclude generated code and temporary test files
generated_*.c
test/mocks/
temp_*.c

# Negation rule: re-include a specific critical security file inside vendor
!vendor/crypto/secure_memcmp.c
```

### Negation Semantics and Traversal Behavior
- `.cgullignore` supports gitignore-style negation rules (`!`). Later patterns override earlier matching rules for the same path (last match wins).
- **Directory Traversal Note**: Unlike native `git` (which prunes excluded directories during directory walking and thus cannot re-include files inside an ignored parent directory), C-GULL traverses nested directories so that negation rules (`!`) can re-include specific files or subdirectories underneath an ignored parent directory (e.g. `!vendor/crypto/secure_memcmp.c` inside `vendor/`).

---

## 🧩 Extending Ruleset: Creating Custom Rules

C-GULL's modular API allows you to implement custom organization-specific security rules in minutes:

```python
# my_custom_rule.py
from cgull.rules.base import BaseRule
from cgull.models import Severity, RuleCategory, Issue, AnalysisEngine

class NoInsecureRandRule(BaseRule):
    rule_id = "CUSTOM-001"
    name = "Insecure PRNG rand() Call"
    impact = Severity.HIGH
    category = RuleCategory.CRYPTO
    description = "rand() and srand() are not cryptographically secure."
    cwe_id = "CWE-338"
    remediation_suggestion = "Use getrandom(), arc4random(), or OpenSSL RAND_bytes()."
    analysis_engine = AnalysisEngine.REGEX

    def scan_line(self, file_path, line_number, line_content, full_code, source_lines):
        issues = []
        if "rand()" in line_content:
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message="Use of predictable PRNG 'rand()'. Vulnerable to seed recovery.",
                engine="Regex"
            ))
        return issues
```

Register it in `cgull.rules.ALL_RULES` to activate it globally across CLI and Web tools!

---

## 🧪 Running the Test Suite & Coverage Standards

C-GULL enforces a **dual test coverage policy** in CI to guarantee both Python code implementation quality and static security rule analyzer correctness.

### 1. Raw Line Coverage Threshold
CI enforces a minimum code line coverage threshold of **88.0%** across the `cgull` package (configured via `pyproject.toml` and `--cov-fail-under=88`).

```bash
# Run unit test suite with coverage enforcement
pytest -v --cov=cgull --cov-report=term-missing --cov-fail-under=88

# Or run specific test modules
python3 -m unittest tests/test_scanner.py
```

### 2. Security Rule Behavioral Coverage
While raw line coverage ensures execution paths are exercised, **rule behavioral coverage** is the primary quality metric for analyzer correctness. Behavioral tests verify that each rule correctly detects true positives and avoids false positives on real C code samples annotated with exact line expectations (`// expect: CGULL-xxx`).

CI enforces a minimum **Rule Behavioral Coverage threshold of 40.0%** across all registered rules (with rule suites in `tests/rules/`).

```bash
# Run standalone Security Rule Behavioral Corpus runner with coverage threshold
python3 tests/run_corpus.py --min-coverage 40.0

# Verify a single rule in isolation
python3 tests/run_corpus.py --rule CGULL-003
```

Coverage thresholds are maintained as minimum baselines and are increased deliberately over time as new rules and corpus test suites are implemented.

---

## 📌 Versioning Policy & Output Schema Versioning

C-GULL maintains clear stability boundaries by separating the **Package Version** from the **Finding / Output Schema Version**:

### Package Versioning (`cgull.__version__`)
- Follows **Semantic Versioning (SemVer 2.0.0)** (`MAJOR.MINOR.PATCH`).
- **PATCH** increments for bug fixes, performance improvements, and internal refactoring that do not break CLI options or python API behavior.
- **MINOR** increments for new static analysis rules, features, CLI options, or backward-compatible API additions.
- **MAJOR** increments for breaking changes to Python module APIs or CLI flag semantics.

### Output Schema Versioning (`schema_version`)
- The JSON output schema includes an explicit top-level `"schema_version"` field (currently `"1"`).
- **Finding / Output Schema Version** changes independently from the package version.
- **Backward-compatible schema additions** (such as adding new optional fields to issue or summary blocks) do not increment `schema_version`.
- **Backward-incompatible schema changes** (such as removing fields, renaming top-level keys, or restructuring issue lists) will increment `schema_version` (e.g. from `"1"` to `"2"`).

---

## 📄 Output Schema (JSON Example)

```json
{
  "schema_version": "1",
  "meta": {
    "tool": "C-GULL",
    "version": "<VERSION>",
    "timestamp": "2026-08-15T21:45:00Z",
    "target_path": "src/",
    "scan_duration_seconds": 0.0124
  },
  "analysis": {
    "parser": "pycparser",
    "status": "success",
    "status_counts": {
      "pycparser-success": 4,
      "fallback-parser": 0,
      "parse-failed": 0
    }
  },
  "summary": {
    "files_discovered": 6,
    "files_analyzed": 4,
    "files_ignored": 2,
    "files_failed": 0,
    "scanned_files_count": 4,
    "total_lines_of_code": 348,
    "total_issues_count": 5,
    "high_severity_count": 3,
    "medium_severity_count": 1,
    "low_severity_count": 1,
    "rules_applied_count": 25,
    "ignored_paths_count": 2,
    "failed_paths_count": 0
  },
  "issues": [
    {
      "rule_id": "CGULL-001",
      "rule_name": "Banned Functions",
      "impact": "High",
      "file_path": "src/packet.c",
      "line_number": 42,
      "column_number": 5,
      "code_snippet": "strcpy(dest_buffer, user_input);",
      "message": "Banned insecure function call 'strcpy': strcpy() does not check destination buffer size.",
      "remediation": "Replace with snprintf(dest, sizeof(dest), \"%s\", src)",
      "cwe_id": "CWE-676 / CWE-120",
      "engine": "Regex",
      "fix_type": "suggested_fix",
      "auto_fix_replacement": null,
      "suggested_fix_replacement": "strncpy_s(dest, dest_size, src, _TRUNCATE) or snprintf(dest, sizeof(dest), \"%s\", src)",
      "confidence": "FULL"
    }
  ]
}
```

---

## 🛠️ Remediation & Fix Classification (`fix_type`)

C-GULL strictly separates mechanically safe transformations from code suggestions and manual architectural reviews:

- **`safe_fix` (`FixType.SAFE_FIX`)**: Mechanically safe transformations that preserve exact program control flow and semantics (e.g., converting `printf(user_input)` to `printf("%s", user_input)`, adding `default:` labels to switch blocks, or adding `(void)` to empty parameter signatures). `auto_fix_replacement` contains the exact replacement code.
- **`suggested_fix` (`FixType.SUGGESTED_FIX`)**: Illustrative code suggestions or replacement patterns (e.g., replacing `strcpy` with `strncpy_s`, converting `atoi` to `strtol`, or inserting OOM error checks) that provide actionable guidance but require human evaluation of buffer boundaries or error handling logic. `suggested_fix_replacement` holds the code suggestion, while `auto_fix_replacement` remains `null`.
- **`manual_review` (`FixType.MANUAL_REVIEW`)**: Vulnerabilities requiring human inspection, secret management redesign, or architectural changes where automatic code replacement is unsafe (e.g., hardcoded secrets where automatically replacing with `getenv()` is not universally correct, or stripping `volatile` qualifiers). Explanatory text is provided in the `remediation` field.

---

## ⚠️ Known Limitations

- **C++ is NOT supported**: C-GULL is strictly designed for C source code (`.c`, `.h`). C++ features (classes, namespaces, templates, references, operator overloading, etc.) are not supported by the parser or rules engine.
- **Heuristic Static Analysis**: C-GULL relies on regex pattern matching and lightweight AST structural checks. It is not a formal verification tool or full symbolic execution solver and may produce false positives or miss complex interprocedural control flow vulnerabilities.
- **Performance on very large or macro-heavy codebases is not yet optimized.** Function/variable extraction is currently regex-based (`O(n)` per file but with a real constant-factor cost), and the `pycparser` cross-check adds further parse time on top of that. On pathological inputs (e.g. thousands of small functions in one file) total scan time can be significant. Use `-j/--jobs` to parallelize across files in the meantime; a follow-up pass on the extraction/parse hot path is planned.
- **AST-tagged rules degrade gracefully when `pycparser` can't parse a file** (see "AST Engine Notes" above) -- the report surfaces each file's exact AST `parse_tier` (`pcpp+pycparser`, `directive-stripped`, or `regex-fallback`) in `file_summaries`, and CI pipelines can enforce non-degraded AST analysis using `--warn-on-fallback`.
- Several rules have a documented **high false-positive rate** by design trade-off -- use inline suppression (`// cgull-ignore`) rather than disabling the rule entirely if it's noisy on your codebase but still valuable.
- **Baseline fingerprints are content-based, not a cryptographic identity.** Two textually-identical findings from the same rule in the same file (e.g. the same unsafe call copy-pasted at two call sites) share a fingerprint; baseline diffing correctly counts "how many instances are new" via multiset comparison, but if you rename/move code such that the *normalized* snippet text changes, the finding will look new even though it's the same underlying issue moved elsewhere. Re-running `--update-baseline` after intentional refactors is the expected workflow.

---

## 🔒 Security & Safe Coding Best Practices

C-GULL encourages defense-in-depth secure coding for embedded, systems, and low-level software engineering:
1. Always compile with `-Wall -Wextra -Werror -Wformat=2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong`.
2. Pair static analysis with dynamic fuzzing (AFL++, LibFuzzer) and runtime sanitizers (ASan, UBSan, MSan).
3. Enforce automated static checks in pre-commit hooks and Pull Request CI workflows.

---

## ⚖️ License
Distributed under the **Apache License 2.0**. See `LICENSE` for details.
