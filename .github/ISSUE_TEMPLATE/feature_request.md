---
name: Feature request
about: Suggest an idea or new security rule for C-GULL
title: '[FEAT] '
labels: enhancement
assignees: ''

---

**Is your feature request related to a problem or new rule idea? Please describe.**
A clear and concise description of the problem or opportunity (e.g., missing rule for a CWE/MISRA guideline, CLI output improvement, or scanner option).

**C-GULL Version**
- Version or branch you are working with (e.g., `0.9.14` or `main`):

**Target Rule ID / Category (if applicable)**
- Proposed Rule ID or Category (e.g., `CGULL-047`, `RuleCategory.MEMORY`, `MISRA-C`):

**Proposed Solution**
A clear description of what you want to happen and how the feature or rule should behave.

**Minimal C Snippet Example**
If suggesting a new rule or analysis feature, provide examples of C code that should trigger or pass the check:

```c
// Code that SHOULD trigger finding:
void vulnerable_example(void) {
    // ...
}

// Code that SHOULD NOT trigger finding (safe case / compliant):
void safe_example(void) {
    // ...
}
```

**Alternatives Considered**
A description of any alternative solutions, workaround scripts, or features considered.

**Additional Context**
Add any other context, standard references (CWE, CERT-C, MISRA C:2012), or links about the feature request here.
