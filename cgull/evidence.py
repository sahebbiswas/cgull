"""Compact, rule-neutral evidence attached to interprocedural findings.

The analysis domains keep their own internal provenance representations.  This
module provides a stable finding-facing vocabulary so rules and reporters do
not need to expose domain implementation details.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Tuple


DEFAULT_EVIDENCE_STEPS = 32


class EvidenceStepKind(str, Enum):
    SOURCE = "source"
    ASSIGNMENT = "assignment"
    ARGUMENT_FORMAL = "argument-formal"
    RETURN_RESULT = "return-result"
    MODELED_EFFECT = "modeled-effect"
    SINK = "sink"


@dataclass(frozen=True)
class EvidenceStep:
    kind: EvidenceStepKind
    file_path: str = ""
    line: int = 0
    column: int = 0
    function_name: str = ""
    identity: str = ""

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind.value}
        if self.file_path:
            result["file"] = self.file_path
        if self.line > 0:
            result["line"] = self.line
        if self.column > 0:
            result["column"] = self.column
        if self.function_name:
            result["function"] = self.function_name
        if self.identity:
            result["identity"] = self.identity
        return result


@dataclass(frozen=True)
class FindingEvidence:
    steps: Tuple[EvidenceStep, ...] = ()
    degradation_reasons: Tuple[str, ...] = ()
    truncated: bool = False

    @property
    def degraded(self) -> bool:
        return bool(self.degradation_reasons)

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": [step.to_dict() for step in self.steps],
            "degraded": self.degraded,
            "degradationReasons": list(self.degradation_reasons),
            "truncated": self.truncated,
        }


def public_degradation_reasons(reasons: Iterable[str]) -> Tuple[str, ...]:
    """Return deterministic finding-facing reason names."""
    values = set(reasons)
    if "EVIDENCE_LIMIT" in values:
        values.remove("EVIDENCE_LIMIT")
        values.add("PROVENANCE_LIMIT")
    return tuple(sorted(values))


def _step_from_value_ref(ref: Any) -> EvidenceStep | None:
    kind = str(getattr(ref, "kind", ""))
    mapping = {
        "SOURCE": EvidenceStepKind.SOURCE,
        "ASSIGNMENT": EvidenceStepKind.ASSIGNMENT,
        "CALL": EvidenceStepKind.ARGUMENT_FORMAL,
        "RETURN": EvidenceStepKind.RETURN_RESULT,
    }
    public_kind = mapping.get(kind)
    if public_kind is None:
        return None
    identity = str(getattr(ref, "identity", "") or "")
    return EvidenceStep(
        kind=public_kind,
        file_path=str(getattr(ref, "file_path", "") or ""),
        line=int(getattr(ref, "line", 0) or 0),
        column=int(getattr(ref, "column", 0) or 0),
        function_name=identity if public_kind is EvidenceStepKind.ARGUMENT_FORMAL else "",
        identity=identity,
    )


def build_value_fact_evidence(
    fact: Any,
    *,
    sink_file: str,
    sink_line: int,
    sink_column: int = 1,
    sink_function: str = "",
    sink_identity: str = "",
    max_steps: int = DEFAULT_EVIDENCE_STEPS,
) -> FindingEvidence:
    """Convert a value fact into bounded, deterministic finding evidence.

    The incoming value-fact evidence is already deterministically ordered by
    the domain.  Preserve that order, drop duplicate public steps, and always
    retain the sink when truncation is necessary.
    """
    if max_steps < 1:
        raise ValueError("max_steps must be at least 1")

    steps = []
    seen = set()
    for ref in getattr(fact, "evidence", ()):
        step = _step_from_value_ref(ref)
        if step is None or step in seen:
            continue
        seen.add(step)
        steps.append(step)

    sink = EvidenceStep(
        kind=EvidenceStepKind.SINK,
        file_path=sink_file,
        line=max(0, sink_line),
        column=max(0, sink_column),
        function_name=sink_function,
        identity=sink_identity,
    )
    if sink not in seen:
        steps.append(sink)

    truncated = len(steps) > max_steps
    if truncated:
        if max_steps == 1:
            steps = [sink]
        else:
            steps = steps[: max_steps - 1] + [sink]

    reasons = set(getattr(fact, "degradations", ()))
    if truncated:
        reasons.add("PROVENANCE_LIMIT")
    return FindingEvidence(
        steps=tuple(steps),
        degradation_reasons=public_degradation_reasons(reasons),
        truncated=truncated or "EVIDENCE_LIMIT" in set(getattr(fact, "degradations", ())),
    )
