"""Finding profiles and report groups, independent of severity and confidence."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from .config import CGullConfig
    from .models import Issue


FOCUSED_SKIPS = {
    "CGULL-018": "Focused profile: goto usage is project policy",
    "CGULL-019": "Focused profile: explicit void style is project policy",
    "CGULL-025": "Focused profile: assertion placement is project policy",
}

# Explicit rule identities keep grouping independent of configured severity.
# Unknown/new rules stay in security/correctness until reviewed for this list.
POLICY_QUALITY_RULES = frozenset({
    "CGULL-013", "CGULL-014", "CGULL-016", "CGULL-017", "CGULL-018",
    "CGULL-019", "CGULL-020", "CGULL-025", "CGULL-041", "CGULL-042",
    "CGULL-043", "CGULL-045", "CGULL-054", "CGULL-055",
})


def with_finding_profile(config: CGullConfig, profile: str | None) -> CGullConfig:
    """Add profile exclusions without mutating loaded config or undoing its skips."""
    if profile not in (None, "focused", "comprehensive"):
        raise ValueError(f"Unknown finding profile: {profile}")
    if profile != "focused":
        return config
    return replace(config, skipped_rules={**FOCUSED_SKIPS, **config.skipped_rules})


def finding_group_counts(issues: Iterable[Issue]) -> dict[str, int]:
    """Count the actual reported findings, including after baseline filtering."""
    counts = {"security_correctness": 0, "policy_quality": 0}
    for issue in issues:
        group = "policy_quality" if issue.rule_id in POLICY_QUALITY_RULES else "security_correctness"
        counts[group] += 1
    return counts
