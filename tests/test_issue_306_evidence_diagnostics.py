import json

from cgull.ast_analyzer import CASTContext
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine, Confidence
from cgull.reporter import ReportGenerator
from cgull.rules.format_string import FormatStringRule
from cgull.semantic_models import (
    SemanticLocation,
    SemanticLocationKind,
    SemanticModelRegistry,
    SourceModel,
)


def _scan(code: str, rule=None):
    scanner = CGullScanner(
        rules=[rule or FormatStringRule()],
        engine_mode=AnalysisEngine.HYBRID,
    )
    return scanner.scan_text(code, file_path="issue306.c", quiet=True)


def test_multihop_finding_names_source_helpers_and_sink_deterministically():
    code = """
int printf(const char *fmt, ...);
char *read_user(void);
const char *one(const char *value) { return value; }
const char *two(const char *value) { return one(value); }
const char *three(const char *value) { return two(value); }
void entry(void) { printf(three(read_user())); }
"""
    registry = SemanticModelRegistry(
        sources={
            "read_user": SourceModel(
                function="read_user",
                outputs=(SemanticLocation(SemanticLocationKind.RETURN),),
            )
        }
    )
    rule = FormatStringRule()
    rule._semantic_models = registry

    issue = next(issue for issue in _scan(code, rule).issues if issue.rule_id == "CGULL-002")

    assert "Flow:" in issue.message
    assert "read_user" in issue.message
    assert "via one, two, three" in issue.message
    assert "issue306.c:7" in issue.message
    assert issue.interprocedural_evidence
    assert issue.evidence_truncated is False


def test_unresolved_call_surfaces_degraded_reason_and_never_claims_safety():
    code = """
int printf(const char *fmt, ...);
char *unknown_format(void);
void entry(void) { printf(unknown_format()); }
"""
    issue = next(issue for issue in _scan(code).issues if issue.rule_id == "CGULL-002")

    assert issue.confidence is Confidence.LIMITED
    assert issue.analysis_degradations == ("UNRESOLVED_CALL",)
    assert "Analysis degraded (UNRESOLVED_CALL)" in issue.message
    assert "must not be interpreted as proof of safety" in issue.message


def test_parser_fallback_is_explicitly_marked():
    code = """int printf(const char *fmt, ...);
void entry(char *user) { printf(user); }
"""
    context = CASTContext(
        functions=[],
        global_variables={},
        source_lines=code.splitlines(),
        raw_source=code,
        clean_source=code,
    )

    issue = FormatStringRule().scan_ast("issue306.c", context)[0]

    assert issue.confidence is Confidence.FALLBACK
    assert issue.analysis_degradations == ("PARSER_FALLBACK",)
    assert "Analysis degraded (PARSER_FALLBACK)" in issue.message


def test_evidence_limit_uses_public_provenance_limit_name():
    from cgull.cfg.value_facts import ValueFact

    fact = ValueFact(degradations=frozenset({"EVIDENCE_LIMIT", "UNRESOLVED_CALL"}))

    assert FormatStringRule._degradation_reasons(fact) == (
        "PROVENANCE_LIMIT",
        "UNRESOLVED_CALL",
    )


def test_sarif_renders_flow_and_limited_confidence_without_schema_changes():
    code = """
int printf(const char *fmt, ...);
char *unknown_format(void);
void entry(void) { printf(unknown_format()); }
"""
    result = _scan(code)
    sarif = json.loads(ReportGenerator.to_sarif(result))
    finding = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "CGULL-002")

    assert "UNRESOLVED_CALL" in finding["message"]["text"]
    assert finding["properties"]["confidence"] == "LIMITED"
    assert finding["locations"][0]["physicalLocation"]["region"]["startLine"] == 4
