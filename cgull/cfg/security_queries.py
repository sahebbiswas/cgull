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
        return any(v.provenance is Provenance.UNKNOWN for v in self.violations)


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

        for node in cfg.nodes.values():
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
                    location = argument.lstrip("& ")
                    provenance = facts.query_provenance(location, node.node_id)
                    validations = facts.query_validation_properties(location, node.node_id)
                    missing = frozenset(requirement.properties - validations)
                    if not missing or provenance is Provenance.TRUSTED:
                        continue

                    violations.append(
                        SecuritySinkViolation(
                            argument_index=index,
                            argument=argument,
                            provenance=provenance,
                            required=requirement.properties,
                            missing=missing,
                        )
                    )

                if violations:
                    findings.append(
                        SecuritySinkFinding(
                            function_name=function_name,
                            sink_name=call.direct_callee
                            or call.callee_expression
                            or "sensitive sink",
                            line_number=getattr(node, "line_number", 1) or 1,
                            expression=getattr(node, "expr_str", ""),
                            violations=tuple(violations),
                        )
                    )

    return tuple(findings)
