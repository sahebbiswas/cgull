"""Trust-boundary security rules backed by shared CFG security dataflow."""

from __future__ import annotations

from typing import List

from .base import BaseRule
from ..ast_analyzer import CASTContext
from ..cfg.security_queries import query_unvalidated_sink_flows
from ..models import AnalysisEngine, Confidence, Issue, RuleCategory, Severity
from ..semantic_models import (
    EMPTY_SEMANTIC_MODELS,
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
        findings = query_unvalidated_sink_flows(ast_ctx, session.semantic_models)
        source_lines = getattr(ast_ctx, "source_lines", ())
        issues: List[Issue] = []

        for finding in findings:
            evidence = []
            for violation in finding.violations:
                required_names = ", ".join(sorted(prop.value for prop in violation.required))
                missing_names = ", ".join(sorted(prop.value for prop in violation.missing))
                parts = [
                    f"arg:{violation.argument_index} '{violation.argument}' has provenance "
                    f"{violation.provenance.value}",
                    f"requires [{required_names}]",
                    f"missing [{missing_names}]",
                ]
                if violation.known_sources:
                    parts.append(f"source [{', '.join(violation.known_sources)}]")
                if violation.observed_validators:
                    parts.append(
                        "validator observed but not guaranteed successful on every sink-reaching "
                        f"path [{', '.join(violation.observed_validators)}]"
                    )
                evidence.append("; ".join(parts))

            snippet = (
                source_lines[finding.line_number - 1]
                if 0 < finding.line_number <= len(source_lines)
                else finding.expression
            )
            message = (
                f"Security-sensitive sink '{finding.sink_name}' is reachable without all required "
                f"validation: {'; '.join(evidence)}. Validation facts are must-properties, so a "
                "property established only on some paths does not satisfy the sink requirement."
            )
            issue = self.create_issue(
                file_path=file_path,
                line_number=finding.line_number,
                code_snippet=snippet,
                message=message,
                engine="AST-CFG",
            )
            if finding.degraded:
                issue.confidence = Confidence.LIMITED
            issues.append(issue)

        return issues
