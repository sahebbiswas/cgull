---
name: Bug report
about: Create a report to help us improve C-GULL
title: '[BUG] '
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is (e.g., false positive, false negative, scan crash, or unexpected output).

**C-GULL Version**
- Output of `cgull --version` or Python package version (e.g., `0.9.14`):

**Rule ID (if applicable)**
- Rule ID involved (e.g., `CGULL-001`, `CGULL-003`, or `N/A`):

**Minimal Reproducing C Snippet**
Please provide a minimal, self-contained C snippet that reproduces the issue:

```c
#include <stdio.h>
#include <stdlib.h>

void reproduce_issue(void) {
    // Add minimal reproducing C code here
}
```

**Expected Behavior**
A clear and concise description of what you expected to happen.

**Actual Behavior / Command Output**
Include CLI command used and error messages, stack traces, or unexpected report output.

```bash
cgull scan test.c
```

**Environment / OS (please complete the following information):**
- OS: [e.g. Ubuntu 22.04, macOS 14, Windows 11]
- Python Version: [e.g. 3.11.4]
- AST dependencies installed: [e.g. pycparser, pcpp, or none]
