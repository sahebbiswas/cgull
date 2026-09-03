from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cgull import CGullScanner
from cgull.analysis_session import AnalysisSession, analysis_session_for
from cgull.models import AnalysisEngine
from cgull.rules.base import BaseRule
from cgull.semantic_models import SemanticModelRegistry, SourceModel, SemanticLocation, SemanticLocationKind


class _SummaryProbeRule(BaseRule):
    rule_id = "TEST-SESSION-SUMMARY"
    name = "Summary session probe"
    analysis_engine = AnalysisEngine.AST

    def __init__(self):
        self.sessions = []

    def scan_ast(self, file_path, ast_ctx):
        session = self.get_analysis_session(ast_ctx)
        self.sessions.append(session)
        _ = session.function_summaries
        return []


class _LegacySignatureRule(BaseRule):
    rule_id = "TEST-SESSION-LEGACY"
    name = "Legacy AST signature probe"
    analysis_engine = AnalysisEngine.AST

    def __init__(self):
        self.calls = 0

    def scan_ast(self, file_path, ast_ctx):
        self.calls += 1
        return []


def test_two_ast_rules_share_one_session_and_one_summary_construction():
    first = _SummaryProbeRule()
    second = _SummaryProbeRule()
    scanner = CGullScanner(rules=[first, second], engine_mode=AnalysisEngine.AST)

    result = scanner.scan_text("int leaf(void) { return 1; }\nint top(void) { return leaf(); }\n")

    assert result.files_failed == 0
    assert len(first.sessions) == 1
    assert len(second.sessions) == 1
    assert first.sessions[0] is second.sessions[0]
    assert first.sessions[0].summary_construction_count == 1


def test_configuration_profiles_never_share_analysis_state():
    probe = _SummaryProbeRule()
    scanner = CGullScanner(rules=[probe], engine_mode=AnalysisEngine.AST)
    from cgull.models import ConfigProfile

    result = scanner.scan_text_profiles(
        "#ifdef A\nint selected(void) { return 1; }\n#else\nint selected(void) { return 2; }\n#endif\n",
        [ConfigProfile("a", {"A": None}), ConfigProfile("b", {})],
    )

    assert result.files_failed == 0
    assert len(probe.sessions) == 2
    assert probe.sessions[0] is not probe.sessions[1]
    assert all(session.summary_construction_count == 1 for session in probe.sessions)


def test_legacy_custom_scan_ast_signature_remains_supported():
    rule = _LegacySignatureRule()
    scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.AST)

    result = scanner.scan_text("int main(void) { return 0; }\n")

    assert result.files_failed == 0
    assert rule.calls == 1


def test_expensive_domains_are_lazy_and_cached():
    class Context:
        pass

    ctx = Context()
    session = AnalysisSession(ctx)
    summary_result = SimpleNamespace(
        summaries={"f": "summary"},
        diagnostics=(),
        iterations_by_scc={},
    )

    with patch("cgull.cfg.call_graph.build_translation_unit_call_graph", return_value="graph") as graph_builder, patch(
        "cgull.cfg.summaries.analyze_function_summaries_detailed", return_value=summary_result
    ) as summary_builder:
        assert graph_builder.call_count == 0
        assert summary_builder.call_count == 0
        assert session.summary_construction_count == 0

        assert session.call_graph == "graph"
        assert session.call_graph == "graph"
        assert session.function_summaries == {"f": "summary"}
        assert session.function_summaries == {"f": "summary"}
        assert session.summary_diagnostics == ()

        assert graph_builder.call_count == 1
        assert summary_builder.call_count == 1
        assert session.summary_construction_count == 1


def test_analysis_session_for_reuses_context_session():
    class Context:
        pass

    ctx = Context()
    first = analysis_session_for(ctx)
    second = analysis_session_for(ctx)

    assert first is second


def test_analysis_session_rejects_different_nonempty_semantic_registries():
    class Context:
        pass

    out = SemanticLocation(SemanticLocationKind.RETURN)
    first_registry = SemanticModelRegistry(
        sources={"source_a": SourceModel("source_a", (out,))}
    )
    second_registry = SemanticModelRegistry(
        sources={"source_b": SourceModel("source_b", (out,))}
    )

    ctx = Context()
    analysis_session_for(ctx, semantic_models=first_registry)

    with pytest.raises(ValueError, match="same semantic model registry"):
        analysis_session_for(ctx, semantic_models=second_registry)


def test_analysis_session_accepts_equivalent_semantic_registry():
    class Context:
        pass

    out = SemanticLocation(SemanticLocationKind.RETURN)
    first_registry = SemanticModelRegistry(
        sources={"source_a": SourceModel("source_a", (out,))}
    )
    equivalent_registry = SemanticModelRegistry(
        sources={"source_a": SourceModel("source_a", (out,))}
    )

    ctx = Context()
    first = analysis_session_for(ctx, semantic_models=first_registry)
    second = analysis_session_for(ctx, semantic_models=equivalent_registry)

    assert first is second
