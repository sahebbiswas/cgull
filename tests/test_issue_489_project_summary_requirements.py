"""Demand-driven project-summary requirements and compatibility regressions."""

import pytest

from cgull.analysis_requirements import (
    ANALYSIS_REQUIREMENTS,
    FUNCTION_SUMMARY,
    OWNERSHIP_SUMMARY,
    POINTER_RANGE_FACTS,
    SECURITY_SUMMARY,
    SIZE_FACTS,
    VALUE_SUMMARY,
    dependency_closure,
    required_analysis_for_rules,
)
from cgull.ast_analyzer import CASTParser
from cgull.models import AnalysisEngine, ScanConfig
from cgull.project_analysis import DOMAINS, ProjectSummaryIndex, prepare_project, profile_key
from cgull.rules import (
    BannedFunctionsRule,
    FormatStringRule,
    PointerRangeBoundsRule,
    UnvalidatedExternalDataSinkRule,
)
from cgull.rules.base import BaseRule
from cgull.rules.memory_management import UseAfterFreeRule


GENERIC_CALLER = "int helper(int); int caller(int x) { return helper(x); }"
GENERIC_CALLEE = "int helper(int x) { return x; }"
UAF_CALLER = """
void release(void *);
void caller(void *p) {
    release(p);
    *(int *)p = 1;
}
"""
UAF_CALLEE = """
void free(void *);
void release(void *p) { free(p); }
"""


def _index(sources=None, *, required_domains=None):
    sources = sources or {"caller.c": GENERIC_CALLER, "callee.c": GENERIC_CALLEE}
    contexts = {name: CASTParser().parse(source) for name, source in sources.items()}
    assert all(ctx.has_pycparser for ctx in contexts.values())
    kwargs = {} if required_domains is None else {"required_domains": required_domains}
    return ProjectSummaryIndex(contexts, **kwargs).build()


def test_dependency_closure_is_central_and_deterministic():
    assert dependency_closure({OWNERSHIP_SUMMARY}) == (
        FUNCTION_SUMMARY,
        OWNERSHIP_SUMMARY,
    )
    pointer = (VALUE_SUMMARY, SIZE_FACTS, POINTER_RANGE_FACTS)
    assert dependency_closure({POINTER_RANGE_FACTS}) == pointer
    assert dependency_closure(reversed(pointer)) == pointer


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        ({"function"}, {"function"}),
        ({"ownership"}, {"function", "ownership"}),
        ({"value"}, {"value"}),
        ({"security"}, {"security"}),
    ],
)
def test_project_index_evaluates_only_required_domains(requested, expected):
    index = _index(required_domains=requested)

    assert set(index.required_domains) == expected
    assert index.outputs
    assert all(set(output) == expected for output in index.outputs.values())
    for domain in DOMAINS:
        assert (index.domain_evaluations[domain] > 0) is (domain in expected)


def test_empty_project_requirement_set_keeps_analysis_lazy():
    index = _index(required_domains=set())

    assert index.required_domains == ()
    assert index.outputs == {}
    assert not any(index.domain_evaluations.values())
    assert all(getattr(ctx, "analysis_session", None) is None for ctx in index.contexts.values())


def test_builtin_rule_metadata_covers_transitive_dependencies():
    assert required_analysis_for_rules([BannedFunctionsRule()]) == ()
    assert required_analysis_for_rules([FormatStringRule()]) == (VALUE_SUMMARY,)
    assert required_analysis_for_rules([UseAfterFreeRule()]) == (
        FUNCTION_SUMMARY,
        OWNERSHIP_SUMMARY,
    )
    assert required_analysis_for_rules([UnvalidatedExternalDataSinkRule()]) == (
        SECURITY_SUMMARY,
    )
    assert required_analysis_for_rules([PointerRangeBoundsRule()]) == (
        VALUE_SUMMARY,
        SIZE_FACTS,
        POINTER_RANGE_FACTS,
    )


def test_legacy_custom_rule_without_metadata_requests_everything():
    class LegacyRule(BaseRule):
        pass

    class LegacySubclass(UseAfterFreeRule):
        pass

    assert required_analysis_for_rules([LegacyRule()]) == ANALYSIS_REQUIREMENTS
    # Built-in metadata is intentionally not inherited by third-party subclasses.
    assert required_analysis_for_rules([LegacySubclass()]) == ANALYSIS_REQUIREMENTS


def test_custom_rule_can_explicitly_opt_into_a_subset():
    class FunctionRule(BaseRule):
        analysis_requirements = frozenset({FUNCTION_SUMMARY})

    assert required_analysis_for_rules([FunctionRule()]) == (FUNCTION_SUMMARY,)


def test_restricted_ownership_index_preserves_enabled_rule_findings():
    sources = {"caller.c": UAF_CALLER, "callee.c": UAF_CALLEE}
    legacy = _index(sources)
    restricted = _index(sources, required_domains={"ownership"})

    def findings(index):
        return [
            (issue.rule_id, issue.line_number, issue.message)
            for issue in UseAfterFreeRule().scan_ast(
                "caller.c", index.contexts["caller.c"]
            )
        ]

    assert findings(restricted) == findings(legacy)
    assert findings(restricted)
    assert restricted.domain_evaluations["function"] > 0
    assert restricted.domain_evaluations["ownership"] > 0
    assert restricted.domain_evaluations["value"] == 0
    assert restricted.domain_evaluations["security"] == 0


def test_prepare_project_passes_active_rule_requirements(tmp_path):
    caller = tmp_path / "caller.c"
    callee = tmp_path / "callee.c"
    caller.write_text(UAF_CALLER, encoding="utf-8")
    callee.write_text(UAF_CALLEE, encoding="utf-8")
    config = ScanConfig.create(rules=[UseAfterFreeRule()], engine_mode=AnalysisEngine.AST)

    units, diagnostics = prepare_project(
        [str(caller), str(callee)],
        lambda _path: config,
    )

    assert not diagnostics
    ctx = units[str(caller)][profile_key(None)].context
    assert set(ctx.project_summaries) == {"function", "ownership"}


def test_prepare_project_keeps_unannotated_custom_rule_conservative(tmp_path):
    class LegacyRule(BaseRule):
        pass

    caller = tmp_path / "caller.c"
    callee = tmp_path / "callee.c"
    caller.write_text(GENERIC_CALLER, encoding="utf-8")
    callee.write_text(GENERIC_CALLEE, encoding="utf-8")
    config = ScanConfig.create(rules=[LegacyRule()], engine_mode=AnalysisEngine.AST)

    units, diagnostics = prepare_project(
        [str(caller), str(callee)],
        lambda _path: config,
    )

    assert not diagnostics
    ctx = units[str(caller)][profile_key(None)].context
    assert set(ctx.project_summaries) == set(DOMAINS)
