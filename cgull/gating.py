"""
CI exit-policy ("gate") counting for C-GULL.

`--fail-on` decides when findings produce a non-zero exit status.  Severity
(`impact`) says how bad a defect would be if real; `confidence` says how well
the engine could prove it.  A finding that the structural engines produced
from the regex-fallback parser tier (``confidence == FALLBACK``) is not fully
proven, so by default it is reported in full but does not fail the gate.
``--strict-confidence`` (or ``[output].strict_confidence = true``) restores
the severity-only behavior.

Regex-engine findings are lexical and do not depend on the parser tier, so
they are always gated on severity alone.  ``LIMITED`` confidence is not
demoted either: it marks rules that are intentionally conservative about
context, not findings produced from a degraded parse.
"""

from dataclasses import dataclass
from typing import Iterable, Optional

from .models import Confidence, Issue, Severity

# Engine label of purely lexical findings; they never depend on the parser tier.
LEXICAL_ENGINE = "regex"


def is_fallback_confidence(issue: Issue) -> bool:
    """True when the finding was produced by a structural engine at FALLBACK confidence."""
    if issue.confidence != Confidence.FALLBACK:
        return False
    return str(issue.engine or "").strip().lower() != LEXICAL_ENGINE


@dataclass(frozen=True)
class GateCounts:
    """Findings per severity, split by whether they are fallback-confidence."""

    high_full: int = 0
    high_fallback: int = 0
    medium_full: int = 0
    medium_fallback: int = 0
    low_full: int = 0
    low_fallback: int = 0
    info_full: int = 0
    info_fallback: int = 0

    @property
    def high(self) -> int:
        return self.high_full + self.high_fallback

    @property
    def fallback_total(self) -> int:
        return self.high_fallback + self.medium_fallback + self.low_fallback + self.info_fallback

    def counted(self, strict_confidence: bool) -> "GateCounts":
        """Counts that participate in the gate under the given policy."""
        if strict_confidence:
            return self
        return GateCounts(
            high_full=self.high_full,
            medium_full=self.medium_full,
            low_full=self.low_full,
            info_full=self.info_full,
        )

    @property
    def medium_or_higher(self) -> int:
        return self.high + self.medium_full + self.medium_fallback

    @property
    def total(self) -> int:
        return self.medium_or_higher + self.low_full + self.low_fallback + self.info_full + self.info_fallback


def count_for_gate(issues: Iterable[Issue]) -> GateCounts:
    """Split findings by severity and fallback-confidence."""
    buckets = {
        (Severity.HIGH, False): 0,
        (Severity.HIGH, True): 0,
        (Severity.MEDIUM, False): 0,
        (Severity.MEDIUM, True): 0,
        (Severity.LOW, False): 0,
        (Severity.LOW, True): 0,
        (Severity.INFO, False): 0,
        (Severity.INFO, True): 0,
    }
    for issue in issues:
        key = (issue.impact, is_fallback_confidence(issue))
        if key in buckets:
            buckets[key] += 1
    return GateCounts(
        high_full=buckets[(Severity.HIGH, False)],
        high_fallback=buckets[(Severity.HIGH, True)],
        medium_full=buckets[(Severity.MEDIUM, False)],
        medium_fallback=buckets[(Severity.MEDIUM, True)],
        low_full=buckets[(Severity.LOW, False)],
        low_fallback=buckets[(Severity.LOW, True)],
        info_full=buckets[(Severity.INFO, False)],
        info_fallback=buckets[(Severity.INFO, True)],
    )


def gate_fails(fail_on: Optional[str], counts: GateCounts, strict_confidence: bool = False) -> bool:
    """Whether `--fail-on <fail_on>` should produce a non-zero exit status."""
    effective = counts.counted(strict_confidence)
    if fail_on == "high":
        return effective.high > 0
    if fail_on == "medium":
        return effective.medium_or_higher > 0
    if fail_on in ("low", "all"):
        return effective.total > 0
    return False


def excluded_by_confidence(fail_on: Optional[str], counts: GateCounts) -> int:
    """How many findings at or above the threshold the default policy left out of the gate."""
    if fail_on == "high":
        return counts.high_fallback
    if fail_on == "medium":
        return counts.high_fallback + counts.medium_fallback
    if fail_on in ("low", "all"):
        return counts.fallback_total
    return 0
