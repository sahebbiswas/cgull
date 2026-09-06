from types import SimpleNamespace

from cgull.evidence import (
    EvidenceStepKind,
    build_value_fact_evidence,
)


def _ref(kind: str, line: int, identity: str):
    return SimpleNamespace(
        kind=kind,
        file_path="flow.c",
        line=line,
        column=1,
        identity=identity,
    )


def test_value_fact_evidence_maps_public_step_kinds_and_keeps_sink():
    fact = SimpleNamespace(
        evidence=(
            _ref("SOURCE", 2, "read_user"),
            _ref("ASSIGNMENT", 3, "fmt"),
            _ref("CALL", 4, "forward"),
            _ref("RETURN", 5, "fmt"),
        ),
        degradations=frozenset(),
    )

    evidence = build_value_fact_evidence(
        fact,
        sink_file="flow.c",
        sink_line=9,
        sink_identity="printf",
    )

    assert [step.kind for step in evidence.steps] == [
        EvidenceStepKind.SOURCE,
        EvidenceStepKind.ASSIGNMENT,
        EvidenceStepKind.ARGUMENT_FORMAL,
        EvidenceStepKind.RETURN_RESULT,
        EvidenceStepKind.SINK,
    ]
    assert evidence.steps[-1].identity == "printf"
    assert evidence.truncated is False


def test_value_fact_evidence_truncates_deterministically_and_marks_limit():
    fact = SimpleNamespace(
        evidence=tuple(_ref("ASSIGNMENT", line, f"v{line}") for line in range(1, 7)),
        degradations=frozenset(),
    )

    first = build_value_fact_evidence(
        fact,
        sink_file="flow.c",
        sink_line=9,
        sink_identity="printf",
        max_steps=3,
    )
    second = build_value_fact_evidence(
        fact,
        sink_file="flow.c",
        sink_line=9,
        sink_identity="printf",
        max_steps=3,
    )

    assert first == second
    assert first.truncated is True
    assert first.degradation_reasons == ("PROVENANCE_LIMIT",)
    assert len(first.steps) == 3
    assert first.steps[-1].kind is EvidenceStepKind.SINK
