"""Finding profiles and report groups, independent of severity and confidence.

Focused skips are the security-oriented init/scan defaults: they disable a small
set of low-severity MISRA/style policy checks that drown external corpus scans
without hiding HIGH/MEDIUM memory or bounds rules. Comprehensive keeps every
registered rule enabled.

Classification is report-only: it labels findings for human summaries so policy
hits are not mistaken for actionable security vulns when those rules remain on.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Dict, Iterable, Optional, Sequence, Tuple

from .models import Issue, Severity
from .rules import get_all_rules

if TYPE_CHECKING:
    from .config import CGullConfig

# Low-severity policy/MISRA checks skipped by the focused (security) profile.
# Safety: every entry must remain Low (validated by validate_focused_profile).
FOCUSED_SKIPS: Dict[str, str] = {
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


def validate_focused_profile() -> None:
    """Refuse focused skips that reference unknown or high/medium-severity rules."""
    rules = {rule.rule_id: rule for rule in get_all_rules()}
    missing = [rule_id for rule_id in FOCUSED_SKIPS if rule_id not in rules]
    if missing:
        raise ValueError(f"Focused profile references unknown rule(s): {', '.join(missing)}")
    unsafe = [
        rule_id
        for rule_id in FOCUSED_SKIPS
        if rules[rule_id].impact in (Severity.HIGH, Severity.MEDIUM)
    ]
    if unsafe:
        raise ValueError(
            "Focused profile safety check failed; refusing to disable high/medium-severity rule(s): "
            + ", ".join(unsafe)
        )


def apply_focused_skips(skipped_rules: Dict[str, str]) -> Dict[str, str]:
    """Merge focused skips into an existing skip map without overriding reasons."""
    validate_focused_profile()
    merged = dict(skipped_rules)
    for rule_id, reason in FOCUSED_SKIPS.items():
        merged.setdefault(rule_id, reason)
    return merged


def with_finding_profile(config: "CGullConfig", profile: str | None) -> "CGullConfig":
    """Add profile exclusions without mutating loaded config or undoing its skips."""
    if profile not in (None, "focused", "comprehensive"):
        raise ValueError(f"Unknown finding profile: {profile}")
    if profile != "focused":
        return config
    validate_focused_profile()
    # Config reasons win over focused defaults for the same rule id.
    return replace(config, skipped_rules={**FOCUSED_SKIPS, **config.skipped_rules})


def is_policy_quality_rule(rule_id: str, category: Optional[object] = None) -> bool:
    """Return True when a rule is MISRA/style/policy rather than security-actionable."""
    del category  # grouping is by explicit rule id, independent of category/severity
    return rule_id in POLICY_QUALITY_RULES


def classify_issue_bucket(issue: Issue) -> str:
    """Return ``security`` or ``policy`` for human report labeling."""
    return "policy" if is_policy_quality_rule(issue.rule_id) else "security"


def finding_group_counts(issues: Iterable[Issue]) -> dict[str, int]:
    """Count the actual reported findings, including after baseline filtering."""
    counts = {"security_correctness": 0, "policy_quality": 0}
    for issue in issues:
        group = "policy_quality" if issue.rule_id in POLICY_QUALITY_RULES else "security_correctness"
        counts[group] += 1
    return counts


def count_security_vs_policy(issues: Sequence[Issue]) -> Tuple[int, int]:
    """Count (security_actionable, policy_quality) findings in *issues*."""
    groups = finding_group_counts(issues)
    return groups["security_correctness"], groups["policy_quality"]


def focused_skip_ids() -> Iterable[str]:
    return tuple(FOCUSED_SKIPS.keys())
