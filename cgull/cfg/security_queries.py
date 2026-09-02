"""High-level shared queries over trust-boundary CFG security facts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Tuple

from .construction import build_cfg, find_function_def
from .security_dataflow import (
    Provenance,
    analyze_security_dataflow,
    analyze_security_summaries,
)
from ..semantic_models import SemanticLocationKind, SemanticModelRegistry, ValidationProperty


@dataclass(frozen=True)
class SecuritySinkViolation:
    """One sink argument whose required validation is not guaranteed."""

    argument_index: int
    argument: str
    provenance: Provenance
    required: FrozenSet[ValidationProperty]
    missing: FrozenSet[ValidationProperty]
    known_sources: Tuple[str, ...] = ()
    observed_validators: Tuple[str, ...] = ()


@dataclass(frozen=True)
class SecuritySinkFinding:
    """Shared query result for one unsafe modeled sink call."""

    function_name: str
    sink_name: str
    line_number: int
    expression: str
    violations: Tuple[SecuritySinkViolation, ...]

    @property
    def degraded(self) -> bool:
        return bool(self.violations) and all(
            v.provenance is Provenance.UNKNOWN for v in self.violations
        )


def _location(value: str) -> str:
    return value.strip().lstrip("&").strip()


def query_unvalidated_sink_flows(
    ast_context: object,
    semantic_models: SemanticModelRegistry,
) -> Tuple[SecuritySinkFinding, ...]:
    """Return modeled sink calls reached without all required validation.

    This is intentionally rule-neutral. It owns CFG enumeration and consumes the
    shared provenance/validation transfer, leaving user-facing rules to decide
    presentation, severity, and reporting metadata.
    """
    if not semantic_models.sinks:
        return ()

    ast = getattr(ast_context, "pycparser_ast", None)
    if ast is None:
        return ()

    summaries = analyze_security_summaries(ast_context, semantic_models)
    findings = []

    for fn in getattr(ast_context, "functions", ()):
        function_name = getattr(fn, "name", None)
        if not function_name:
            continue
        funcdef = find_function_def(ast, function_name)
        if funcdef is None:
            continue

        cfg = build_cfg(funcdef, line_map=getattr(ast_context, "line_map", None))
        facts = analyze_security_dataflow(cfg, semantic_models, summaries)
        source_events = []
        validator_events = []

        for event_node in cfg.nodes.values():
            event_line = getattr(event_node, "line_number", 1) or 1
            for event_call in getattr(event_node, "calls", ()):
                source = semantic_models.source_for(event_call)
                if source is not None:
                    for output in source.outputs:
                        destination = None
                        if output.kind is SemanticLocationKind.RETURN:
                            destination = event_call.result_target
                        elif (
                            output.kind is SemanticLocationKind.OUTPUT_ARGUMENT
                            and output.argument_index is not None
                            and output.argument_index < len(event_call.actual_arguments)
                        ):
                            destination = event_call.actual_arguments[output.argument_index]
                        if destination:
                            source_events.append(
                                (event_line, _location(destination), source.function)
                            )

                validator = semantic_models.validator_for(event_call)
                if validator is not None:
                    index = validator.target.argument_index
                    if (
                        validator.target.kind
                        in {SemanticLocationKind.ARGUMENT, SemanticLocationKind.OUTPUT_ARGUMENT}
                        and index is not None
                        and index < len(event_call.actual_arguments)
                    ):
                        validator_events.append(
                            (
                                event_line,
                                _location(event_call.actual_arguments[index]),
                                validator.function,
                                validator.property,
                            )
                        )

        for node in cfg.nodes.values():
            sink_line = getattr(node, "line_number", 1) or 1
            for call in getattr(node, "calls", ()):
                sink = semantic_models.sink_for(call)
                if sink is None:
                    continue

                violations = []
                for requirement in sink.requirements:
                    index = requirement.location.argument_index
                    if requirement.location.kind not in {
                        SemanticLocationKind.ARGUMENT,
                        SemanticLocationKind.OUTPUT_ARGUMENT,
                    } or index is None or index >= len(call.actual_arguments):
                        continue

                    argument = call.actual_arguments[index]
                    location = _location(argument)
                    provenance = facts.query_provenance(location, node.node_id)
                    validations = facts.query_validation_properties(location, node.node_id)
                    missing = frozenset(requirement.properties - validations)
                    if not missing or provenance is Provenance.TRUSTED:
                        continue

                    known_sources = tuple(
                        sorted(
                            {
                                source_name
                                for line, event_location, source_name in source_events
                                if line <= sink_line and event_location == location
                            }
                        )
                    )
                    observed_validators = tuple(
                        sorted(
                            {
                                validator_name
                                for line, event_location, validator_name, prop in validator_events
                                if line <= sink_line
                                and event_location == location
                                and prop in requirement.properties
                            }
                        )
                    )
                    violations.append(
                        SecuritySinkViolation(
                            argument_index=index,
                            argument=argument,
                            provenance=provenance,
                            required=requirement.properties,
                            missing=missing,
                            known_sources=known_sources,
                            observed_validators=observed_validators,
                        )
                    )

                if violations:
                    findings.append(
                        SecuritySinkFinding(
                            function_name=function_name,
                            sink_name=call.direct_callee
                            or call.callee_expression
                            or "sensitive sink",
                            line_number=sink_line,
                            expression=getattr(node, "expr_str", ""),
                            violations=tuple(violations),
                        )
                    )

    return tuple(findings)
