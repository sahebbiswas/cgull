# Contributing to C-GULL

Thank you for your interest in contributing to **C-GULL** (*Code Guardian for Unchecked Logic & Leaks*)! This guide documents our architecture, workflow expectations, rule-authoring patterns, inline suppression & baseline diffing mechanisms, and the verification checks required for Pull Requests.

---

## 🛠️ Development Environment Setup & Workflow Expectations

### 1. Environment Setup

C-GULL supports zero-dependency scanning with standard Python 3.10+, but running tests and developing AST/CFG rules requires optional AST dependencies (`pycparser`, `pcpp`) and development packages (`pytest`, `pytest-cov`, `jsonschema`).

Set up your local environment in editable mode with development extras:

```bash
git clone https://github.com/sahebbiswas/cgull.git
cd cgull

# Install in editable mode with AST parsing & dev dependencies
pip install -e ".[ast,dev]"
```

### 2. Disciplined Internal Workflow & PR / Patch Format

To maintain repository quality and streamline code reviews, please follow these guidelines when submitting Pull Requests or patches:

- **Synced to Upstream Tip**: Always rebase your feature or bugfix branch on top of the latest `main`/`master` tip before submitting a PR or generating a patch file (`git rebase main`).
- **Atomic Commits & Descriptive Messages**: Break work into logical, atomic commits. Write clear, concise commit summary lines (under 50 characters) followed by detailed body explanations when necessary.
- **Clean Patch-File PRs**: Ensure patches do not include temporary files, untracked artifacts, or unrelated formatting changes.
- **CHANGELOG Maintenance & Version Bumps**: Keep `CHANGELOG.md` updated following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) standards. New features, rules, fixes, and CLI options should be listed under the `[Unreleased]` section. When bumping `__version__` in `cgull/__init__.py`, move `[Unreleased]` entries into a new version section header with the release date.
- **CI Gate Enforcement**: PRs will only be merged if all automated tests, corpus behavioral gates, and benchmark quality thresholds pass cleanly.

---

## 🧩 Authoring New Security & Compliance Rules

C-GULL rules inherit from `BaseRule` (defined in `cgull/rules/base.py`). Rules are organized into category subpackages under `cgull/rules/`:
- `banned_functions.py` (String and function safety rules)
- `memory_management.py` (Allocation, lifetime, and pointer rules)
- `crypto_and_safety.py` (Cryptography, privilege, and race condition rules)
- `types_and_arrays.py` (Array bounds, overflow, pointer arithmetic rules)
- `misra_and_style.py` (MISRA guidelines, variable shadowing, code quality)

For a quick-start summary of extending the ruleset, see the [Extending Ruleset: Creating Custom Rules](README.md#%EF%B8%8F-extending-ruleset-creating-custom-rules) section in `README.md`.

### 1. Rule Base Classes & Execution Engines

Rules specify an `analysis_engine` (`AnalysisEngine.REGEX`, `AnalysisEngine.AST`, or `AnalysisEngine.HYBRID`) and implement line-by-line scanning (`scan_line`) and/or structural AST scanning (`scan_ast`).

#### Regex-Based Rules (`AnalysisEngine.REGEX`)
Use regex pattern matching for lightweight lexical checks across single lines.

```python
from typing import List
from cgull.rules.base import BaseRule
from cgull.models import Issue, Severity, RuleCategory, AnalysisEngine, FixType

class UnsafeIntegerConversionsRule(BaseRule):
    rule_id = "CGULL-012"
    name = "Unsafe Integer Conversions"
    impact = Severity.MEDIUM
    category = RuleCategory.ARITHMETIC
    description = "atoi(), atol(), and atoll() do not detect overflow or invalid input."
    cwe_id = "CWE-704"
    remediation_suggestion = "Replace with strtol() or strtoul() and validate errno."
    analysis_engine = AnalysisEngine.REGEX

    def scan_line(
        self,
        file_path: str,
        line_number: int,
        line_content: str,
        full_code: str,
        source_lines: List[str],
        masked_line_content: str = "",
    ) -> List[Issue]:
        issues = []
        # Use masked_line_content to prevent matching inside string literals
        target = masked_line_content if masked_line_content else line_content
        if "atoi(" in target:
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message="Use of atoi() lacks error handling and overflow detection.",
                engine="Regex",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement="strtol(str, NULL, 10)",
            ))
        return issues
```

> **Note on String/Comment Masking**: Always prefer `masked_line_content` when inspecting call syntax. `masked_line_content` replaces character and string contents with `'x'` placeholders (e.g. `"please don't use gets()"` becomes `"xxxxxxxxxxxxxxxxxxxxxxx"`), preventing false positives on comments or text inside string literals.

#### AST / CFG-Based Rules (`AnalysisEngine.AST`)
Use `scan_ast` for structural or control-flow aware checks. `scan_ast` receives `ast_ctx: CASTContext`, which provides function lists (`ast_ctx.functions`), Control Flow Graphs (`fn.cfg_nodes` / `fn.structured_cfg`), variable declarations, and struct metadata (`ast_ctx.resolve_struct_def`).

```python
from typing import List
from cgull.rules.base import BaseRule
from cgull.models import Issue, Severity, RuleCategory, AnalysisEngine, FixType
from cgull.ast_analyzer import CASTContext

class ReturnStackVariableRule(BaseRule):
    rule_id = "CGULL-038"
    name = "Return Address of Stack Variable"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Returning pointer to automatic local variable leads to dangling reference."
    cwe_id = "CWE-562"
    remediation_suggestion = "Allocate memory dynamically or pass buffer as parameter."
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            local_vars = {v.name for v in fn.variables.values()}
            for node in fn.cfg_nodes:
                if node.kind == "return" and node.expr_str:
                    # Perform AST node / CFG inspection...
                    pass
        return issues
```

### 2. Remediations & Fix Type Classification (`fix_type`)

C-GULL strictly classifies issue fixes to prevent unsafe auto-refactoring:

- **`FixType.SAFE_FIX`**: Mechanically safe transformations that strictly preserve program semantics and control flow (e.g., changing `printf(buf)` to `printf("%s", buf)` or adding `default:` labels to switch statements). Provide the replacement string via `auto_fix_replacement`.
- **`FixType.SUGGESTED_FIX`**: Illustrative code patterns or replacement functions (e.g., replacing `strcpy` with `strncpy_s`, converting `atoi` to `strtol`). Provide the suggestion via `suggested_fix_replacement`. `auto_fix_replacement` remains `None`.
- **`FixType.MANUAL_REVIEW`**: Complex security findings requiring human architectural design or secret management changes (e.g. hardcoded credentials, use-after-free). Leave both replacement parameters `None`.

### 3. Registering Rule IDs

All active rules must be registered in `cgull/rules/__init__.py`:

1. Import your rule class.
2. Add it to `ALL_RULES` in the appropriate impact section (`High Impact`, `Medium Impact`, or `Low Impact`).
3. Ensure `RULE_REGISTRY` registers `rule_cls.rule_id`.

```python
# cgull/rules/__init__.py
from .my_category import MyNewRule

ALL_RULES: List[Type[BaseRule]] = [
    # ...
    MyNewRule,
]
```

### 4. Writing Behavioral Corpus Tests

Every rule should include test cases in `tests/rules/` annotated with exact line expectations (`// expect: CGULL-XXX`).

Create a C source test file (e.g., `tests/rules/cgull_012_unsafe_integer_conversions.c`):

```c
#include <stdio.h>
#include <stdlib.h>

void test_func(const char *str) {
    int val = atoi(str); // expect: CGULL-012
    printf("Val: %d\n", val);
}
```

Behavioral corpus tests are validated automatically by running `python tests/run_corpus.py`.

---

## 🔇 Inline Suppression & Baseline Fingerprinting Systems

### 1. `.cgullignore` Path Filtering (`cgull/ignore.py`)
`CGullIgnoreFilter` implements standard `.gitignore` glob semantics for directory traversal and path exclusion:
- Supports wildcard patterns (`*.o`), directory anchors (`/build/`), double-star globbing (`vendor/**`), and comment lines (`#`).
- Supports negation rules (`!vendor/crypto/secure_memcmp.c`). Unlike standard `git` (which prunes excluded directories during directory walking and cannot re-include files inside an ignored parent), C-GULL's `should_prune_dir` inspects `_negation_could_match_under` to ensure negated files within ignored parent directories are reached and scanned.

### 2. Inline Suppression Directives (`cgull/utils.py`)
`SuppressionMap` parses line comments (`//`) and block comments (`/* */`) using `_SUPPRESS_RE` to construct line-based suppression rules:
- `// cgull-ignore`: suppresses all rules on the same line.
- `// cgull-ignore: CGULL-001,CGULL-003`: suppresses specific rule IDs on the same line.
- `// cgull-disable-next-line CGULL-007` or `// cgull-ignore-next-line`: suppresses rules on line `N + 1`.
- `/* cgull-disable-line CGULL-019 */`: inline block comment suppression.

### 3. Content Fingerprinting (`compute_issue_fingerprint`)
To track findings stably across code refactoring without breaking when unrelated edits shift line numbers, `compute_issue_fingerprint` generates a 16-character SHA-256 hash derived from:
```
SHA256(rule_id | relative_file_path | normalized_code_snippet)[:16]
```
`normalized_code_snippet` collapses all whitespace sequences to a single space.

### 4. Baseline Multiset Matching (`cgull/baseline.py`)
Baseline reports (`--baseline baseline.json`) represent previously accepted findings:
- `load_baseline_fingerprints` loads fingerprints into a Python `Counter` (multiset).
- Multi-occurrence matching: if a file contains two textually identical occurrences of a flaw, `Counter` tracking guarantees that fixing *one* occurrence correctly reports *one* remaining issue as pre-existing and does not hide the second occurrence.
- `apply_baseline` compares current scan findings against `baseline_counts`, computing `baseline_new_count` and `baseline_resolved_count`.

---

## 🏁 Local PR Verification Checklist & CI Gates

Before submitting a Pull Request, verify that your changes pass all local CI verification checks. CI runs these three verification gates on every push and PR:

```bash
# 1. Run full unit test suite with raw code coverage enforcement (must be >= 88.0%)
pytest -v --cov=cgull --cov-report=term-missing

# 2. Run Security Rule Behavioral Corpus runner (must achieve 100.0% coverage)
python tests/run_corpus.py --min-coverage 100.0

# 3. Run Focused NIST Juliet Benchmark runner (must meet >= 0.90 F1 score threshold)
python benchmarks/run_juliet.py --ci --min-f1 0.90
```

The corpus runner prints the current **Rule Behavioral Coverage** and the **Required Min Coverage** on every full-corpus run, so contributors and CI logs can see the measured percentage alongside the enforced gate.

### Summary of Coverage & Quality Thresholds
| Verification Gate | Command | Threshold | Description |
| :--- | :--- | :--- | :--- |
| **Unit Test Coverage** | `pytest -v --cov=cgull` | **>= 88.0%** | Raw line coverage across `cgull` package. |
| **Behavioral Corpus** | `python tests/run_corpus.py --min-coverage 100.0` | **100.0%** | Percentage of registered rules verified against annotated `.c` test files; current and required percentages are printed by the runner. |
| **Juliet Benchmark** | `python benchmarks/run_juliet.py` | **>= 0.90** | F1 detection score against Juliet test oracle suite (`--ci` runner). |
