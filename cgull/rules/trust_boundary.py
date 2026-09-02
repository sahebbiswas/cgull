"""Trust-boundary security rules backed by shared CFG security dataflow."""

from __future__ import annotations

from typing import List

from .base import BaseRule
from ..ast_analyzer import CASTContext
from ..cfg import build_cfg, find_function_def
from ..cfg.security_dataflow import (
    Provenance,
    analyze_security_dataflow,
    analyze_security_summaries,
)
from ..models import AnalysisEngine, Confidence, Issue, RuleCategory, Severity
from ..semantic_models import (
    EMPTY_SEMANTIC_MODELS,
    SemanticLocationKind,
    SemanticModelRegistry,
    TUAnalysisSession,
)


class UnvalidatedExternalDataSinkRule(BaseRule):
    """Report external or unresolved data reaching a modeled sink without validation."""

    rule_id = "CGULL-047"
    name = "Externally Controlled Data Reaches Sensitive Sink Without Required Validation"
    impact = Severity.HIGH
    category = RuleCategory.CONTROL_FLOW
    description = (
        "Detects externally controlled or conservatively unresolved data reaching a modeled "
        "security-sensitive sink when one or more typed validation requirements are not "
        "guaranteed on every path."
    )
    implementation_method = "AST + CFG security dataflow"
    implementation_complexity = "High"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-20"
    remediation_suggestion = (
        "Validate externally controlled data before the sensitive operation and ensure every "
        "path reaching the sink establishes each validation property required by the sink model."
    )
    sample_vulnerable_code = (
        "mailbox_read(&msg);\n"
        "flash_write(msg.addr, msg.data, msg.len);"
    )
    sample_remediated_code = (
        "mailbox_read(&msg);\n"
        "if (!validate_bounds(&msg)) return;\n"
        "flash_write(msg.addr, msg.data, msg.len);"
    )
    analysis_engine = AnalysisEngine.AST

    def __init__(self) -> None:
        self._semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS

    def set_semantic_models(self, registry: SemanticModelRegistry) -> None:
        """Receive the immutable project semantic registry during rule configuration."""
        if isinstance(registry, SemanticModelRegistry):
            self._semantic_models = registry

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        if not getattr(ast_ctx, "has_pycparser", False) or getattr(ast_ctx, "pycparser_ast", None) is None:
            return []

        session = TUAnalysisSession(ast_ctx, self._semantic_models)
        registry = session.semantic_models
        if not registry.sinks:
            return []

        summaries = analyze_security_summaries(ast_ctx, registry)
        issues: List[Issue] = []

        for fn in getattr(ast_ctx, "functions", ()):
            function_name = getattr(fn, "name", None)
            if not function_name:
                continue
            funcdef = find_function_def(ast_ctx.pycparser_ast, function_name)
            if funcdef is None:
                continue

            cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, "line_map", None))
            facts = analyze_security_dataflow(cfg, registry, summaries)

            for node in cfg.nodes.values():
                for call in getattr(node, "calls", ()):
                    sink = registry.sink_for(call)
                    if sink is None:
                        continue

                    missing_evidence = []
                    has_unknown = False
                    for requirement in sink.requirements:
                        index = requirement.location.argument_index
                        if requirement.location.kind not in {
                            SemanticLocationKind.ARGUMENT,
                            SemanticLocationKind.OUTPUT_ARGUMENT,
                        } or index is None or index >= len(call.actual_arguments):
                            continue

                        location = call.actual_arguments[index].lstrip("& ")
                        provenance = facts.query_provenance(location, node.node_id)
                        validations = facts.query_validation_properties(location, node.node_id)
                        missing = frozenset(requirement.properties - validations)
                        if not missing:
                            continue
                        if provenance is Provenance.TRUSTED:
                            continue
                        if provenance is Provenance.UNKNOWN:
                            has_unknown = True

                        missing_names = ", ".join(sorted(prop.value for prop in missing))
                        required_names = ", ".join(
                            sorted(prop.value for prop in requirement.properties)
                        )
                        missing_evidence.append(
                            f"arg:{index} '{call.actual_arguments[index]}' has provenance "
                            f"{provenance.value}; requires [{required_names}], missing [{missing_names}]"
                        )

                    if not missing_evidence:
                        continue

                    sink_name = call.direct_callee or call.callee_expression or "sensitive sink"
                    line_number = getattr(node, "line_number", 1) or 1
                    source_lines = getattr(ast_ctx, "source_lines", ())
                    snippet = (
                        source_lines[line_number - 1]
                        if 0 < line_number <= len(source_lines)
                        else getattr(node, "expr_str", "")
                    )
                    message = (
                        f"Security-sensitive sink '{sink_name}' is reachable without all required "
                        f"validation: {'; '.join(missing_evidence)}. "
                        "Validation facts are must-properties, so a property established only on "
                        "some paths does not satisfy the sink requirement."
                    )
                    issue = self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=snippet,
                        message=message,
                        engine="AST-CFG",
                    )
                    if has_unknown:
                        issue.confidence = Confidence.LIMITED
                    issues.append(issue)

        return issues
