"""Semantic rule attribution for Juliet testcase families.

The top-level CWE map intentionally stays broad. Some Juliet CWE families
contain multiple bug shapes, so upstream testcase files need a second layer of
rule applicability before they contribute to a rule's denominator.
"""

from __future__ import annotations

from pathlib import Path
from typing import AbstractSet

CWE563_DEAD_STORE = "dead-store"
CWE563_DECLARATION_ONLY = "declaration-only"
CWE563_UNCLASSIFIED = "unclassified"

# Juliet 1.3 CWE-563 template families whose bad oracle contains a write whose
# previous/new value is not subsequently read. Type and flow-variant suffixes
# are deliberately ignored by matching the stable template-family marker.
_CWE563_DEAD_STORE_MARKERS = (
    "__unused_value_",
    "__unused_init_variable_",
    "__unused_global_value_",
    "__unused_static_global_value_",
    "__unused_parameter_value_",
    "__unused_class_member_value_",
)

# These families exercise an unused declaration/member/parameter rather than a
# dead store. They must not become CGULL-042 false negatives merely because
# Juliet groups them under the same CWE-563 directory.
_CWE563_DECLARATION_ONLY_MARKERS = (
    "__unused_uninit_variable_",
    "__unused_global_variable_",
    "__unused_static_global_variable_",
    "__unused_parameter_variable_",
    "__unused_class_member_variable_",
)


def cwe563_semantic_family(path: str | Path) -> str:
    """Classify a pinned Juliet CWE-563 testcase by template semantics.

    Unknown families fail closed as ``unclassified`` so an upstream fixture
    addition cannot silently expand CGULL-042's benchmark denominator.
    """

    name = Path(path).name.lower()
    if any(marker in name for marker in _CWE563_DEAD_STORE_MARKERS):
        return CWE563_DEAD_STORE
    if any(marker in name for marker in _CWE563_DECLARATION_ONLY_MARKERS):
        return CWE563_DECLARATION_ONLY
    return CWE563_UNCLASSIFIED


def applicable_rules_for_juliet_case(
    cwe: str,
    path: str | Path,
    mapped_rules: AbstractSet[str],
) -> set[str]:
    """Return canonical mapped rules that semantically apply to one testcase."""

    rules = set(mapped_rules)
    if cwe != "CWE-563" or "CGULL-042" not in rules:
        return rules
    if cwe563_semantic_family(path) != CWE563_DEAD_STORE:
        rules.discard("CGULL-042")
    return rules
